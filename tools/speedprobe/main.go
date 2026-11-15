// speedprobe - минимальный измеритель скорости скачивания для форка v2rayNG.
//
// Зачем нужен отдельный бинарник
// ------------------------------
// Проверка профиля FPTN выполняется в изолированном network namespace
// (см. FptnProbeRunner), поэтому закачку нельзя выполнить из Java-кода
// приложения: JVM работает в основном сетевом пространстве и физически не видит
// TUN, поднятый внутри netns. Нужен внешний процесс, запускаемый через
// `ip netns exec`.
//
// Использовать системный `curl` нельзя: он НЕ входит в состав toybox и появился
// в AOSP только с Android 8.0, тогда как minSdk приложения - 24 (Android 7.0).
// На части устройств его просто нет, и функция молча перестала бы работать.
// `nc` из toybox есть всегда, но не умеет TLS, а тестовые зеркала - HTTPS.
//
// Поэтому замер выполняет этот маленький инструмент: только стандартная
// библиотека Go (net/http поддерживает TLS из коробки), статическая сборка
// CGO_ENABLED=0, никаких зависимостей от vendor-бинарников устройства.
//
// Контракт вывода
// ---------------
// Печатает ровно одну строку результата на попытку:
//
//	ATTEMPT <bytes> <seconds>
//
// где <bytes> - сколько байт реально прочитано из тела ответа, <seconds> -
// длительность в секундах с плавающей точкой (формат curl-совместимый, чтобы
// разбор в FptnProbeRunner.parseAttempts был одинаковым для любого источника).
// При ошибке печатается ATTEMPT 0 <seconds> и ненулевой код возврата не
// используется намеренно: вызывающий скрипт трактует ноль байт как неудачную
// попытку и переключается на следующее зеркало.
//
// Дополнительно печатаются служебные строки PROBE_* для диагностики; они не
// влияют на разбор ATTEMPT.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// resolveVia резолвит домен через явно указанный DNS-сервер (ip:port), а не через
// системный /etc/resolv.conf. Используется для гарантии, что запрос уйдёт именно
// в DNS из настроек клиента, минуя кэш и fake-IP активного VPN.
//
// Реализовано стандартным net.Resolver с подменой Dial: никакого cgo, чистый Go.
func resolveVia(ctx context.Context, server, host string) ([]string, error) {
	// Если server без порта, добавляем стандартный 53.
	addr := server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return r.LookupHost(ctx, host)
}

func main() {
	var (
		urlArg     = flag.String("url", "", "URL для скачивания (обязательно)")
		mode       = flag.String("mode", "speed", "режим: speed (байты/время) или delay (TTFB)")
		maxBytes   = flag.Int64("bytes", 10*1024*1024, "сколько байт тела прочитать (режим speed)")
		timeoutSec = flag.Int64("timeout", 15, "общий таймаут попытки, секунд")
		insecure   = flag.Bool("insecure", false, "не проверять сертификат (как в HttpUtil клиента)")
		dnsServer  = flag.String("dns", "", "DNS-сервер для резолва (ip:port), пусто = системный resolv.conf")
	)
	flag.Parse()

	if *mode != "speed" && *mode != "delay" {
		fmt.Fprintf(os.Stderr, "PROBE_ERROR: неизвестный -mode %q (ожидается speed или delay)\n", *mode)
		os.Exit(2)
	}

	if *urlArg == "" {
		fmt.Fprintln(os.Stderr, "PROBE_ERROR: --url обязателен")
		os.Exit(2)
	}
	if *maxBytes <= 0 {
		*maxBytes = 1
	}
	if *timeoutSec <= 0 {
		*timeoutSec = 1
	}

	// Транспорт: как и в HttpUtil клиента, проверка сертификата отключается,
	// потому что форк намеренно не даёт TLS-валидации ломать служебные загрузки
	// в ограничительных сетях (middlebox рвёт рукопожатия).
	tlsCfg := &tls.Config{InsecureSkipVerify: *insecure}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 15 * time.Second,
	}

	// Если явно указан DNS-сервер, резолвим через него вручную и подключаемся
	// по IP. Это гарантирует, что использован именно DNS из настроек клиента,
	// а не кэш или fake-IP активного VPN.
	dialContext := dialer.DialContext
	if *dnsServer != "" {
		dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolveVia(ctx, *dnsServer, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("нет адресов для %s", host)
			}
			return nil, lastErr
		}
	}

	client := &http.Client{
		Timeout: time.Duration(*timeoutSec) * time.Second,
		Transport: &http.Transport{
			DialContext:           dialContext,
			TLSClientConfig:       tlsCfg,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: time.Duration(*timeoutSec) * time.Second,
			MaxIdleConns:          2,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("слишком много редиректов")
			}
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, *urlArg, nil)
	if err != nil {
		fmt.Printf("ATTEMPT 0 %.6f\n", 0.0)
		fmt.Fprintf(os.Stderr, "PROBE_ERROR: некорректный URL: %v\n", err)
		os.Exit(0)
	}
	req.Header.Set("User-Agent", "v2rayNG-speedprobe/1.0")
	req.Header.Set("Connection", "close")

	started := time.Now()
	var read int64

	resp, err := client.Do(req)
	if err != nil {
		elapsedErr := time.Since(started).Seconds()
		if *mode == "delay" {
			// Нулевая задержка трактуется вызывающим кодом как "измерить не
			// удалось" (parseDelay отбрасывает <= 0), поэтому не печатаем DELAY.
			fmt.Fprintf(os.Stderr, "PROBE_ERROR: запрос не выполнен: %v\n", err)
		} else {
			fmt.Printf("ATTEMPT 0 %.6f\n", elapsedErr)
			fmt.Fprintf(os.Stderr, "PROBE_ERROR: запрос не выполнен: %v\n", err)
		}
		os.Exit(0)
	}
	defer resp.Body.Close()

	// Режим delay: интересует время до получения ответа (TTFB), тело не читаем.
	// Это аналог curl -w '%{time_starttransfer}', который использовался раньше,
	// но без зависимости от наличия curl на устройстве.
	if *mode == "delay" {
		ttfb := time.Since(started).Seconds()
		fmt.Printf("DELAY %.6f\n", ttfb)
		fmt.Fprintf(os.Stderr, "PROBE_INFO: status=%d ttfb=%.3fs\n", resp.StatusCode, ttfb)
		os.Exit(0)
	}

	// Читаем не больше maxBytes и не дольше таймаута: ровно та же семантика,
	// что у downloadOnce() в WhitelistSpeedTester, чтобы результаты FPTN и
	// остальных профилей были сопоставимы.
	deadline := started.Add(time.Duration(*timeoutSec) * time.Second)
	buf := make([]byte, 64*1024)
	for read < *maxBytes {
		if time.Now().After(deadline) {
			break
		}
		if limit := *maxBytes - read; int64(len(buf)) > limit {
			buf = buf[:limit]
		}
		n, err := resp.Body.Read(buf)
		read += int64(n)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(started).Seconds()
	if elapsed <= 0 {
		elapsed = 0.000001
	}

	fmt.Printf("ATTEMPT %d %.6f\n", read, elapsed)
	fmt.Fprintf(os.Stderr, "PROBE_INFO: status=%d read=%d elapsed=%.3fs\n", resp.StatusCode, read, elapsed)
}
