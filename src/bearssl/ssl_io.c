/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"

// <MS>
#include <Arduino.h>
#include "ms_semphr.h"
//#include "esp_debug_helpers.h"

/* 16.11.2026 - Optional I/O failure diagnostics, without plaintext-byte timing. */
#if defined(MS_OTA_DIAGNOSTICS)
#include <inttypes.h>
#include "esp_timer.h"
#include "freertos/task.h"

static uint64_t
sslio_diagnostic_now_ms(void)
{
	return (uint64_t)esp_timer_get_time() / 1000;
}

static void
sslio_diagnostic_read(br_sslio_context *ctx, size_t len)
{
	const uint64_t now = sslio_diagnostic_now_ms();
	/* 16.11.2026 - Timestamp only ciphertext progress, never each plaintext byte. */
	if (ctx->diagnostic_read_seen) {
		const uint64_t gap = now - ctx->diagnostic_last_read_ms;
		if (gap > ctx->diagnostic_max_read_gap_ms) {
			ctx->diagnostic_max_read_gap_ms = gap;
		}
	}
	ctx->diagnostic_last_read_ms = now;
	++ctx->diagnostic_positive_reads;
	ctx->diagnostic_read_bytes += len;
	ctx->diagnostic_read_seen = 1;
}

static void
sslio_diagnostic_failure(br_sslio_context *ctx, const char *reason,
	size_t requested, int returned, int conflict)
{
	const int err = br_ssl_engine_last_error(ctx->engine);
	if (conflict) {
		/* A nonterminal target conflict must not hide a later transport error. */
		if (ctx->diagnostic_conflict_logged) { return; }
		ctx->diagnostic_conflict_logged = 1;
	} else {
		/* Normal TLS closure is not an error; repeated reads must not flood logs. */
		if (err == BR_ERR_OK || ctx->diagnostic_failure_logged) { return; }
		ctx->diagnostic_failure_logged = 1;
	}
	const uint64_t now = sslio_diagnostic_now_ms();
	const uint64_t age = ctx->diagnostic_read_seen ?
		now - ctx->diagnostic_last_read_ms : 0;
	const uint64_t max_gap = age > ctx->diagnostic_max_read_gap_ms ?
		age : ctx->diagnostic_max_read_gap_ms;
	const TaskHandle_t task = xTaskGetCurrentTaskHandle();
	log_printf("[BEARSSL-IO] reason=%s err=%d tls=%p io=%p client=%p task=%s/%p uptime_ms=%" PRIu64
		" read_seen=%u last_rx_age_ms=%" PRIu64 " since_init_ms=%" PRIu64
		" requested=%u returned=%d rx_total=%" PRIu64
		" positive_reads=%" PRIu64 " zero_reads=%" PRIu64 " max_rx_gap_ms=%" PRIu64 "\n",
		reason, err, (void *)ctx->engine, (void *)ctx, ctx->read_context,
		pcTaskGetName(task), (void *)task, now,
		(unsigned)ctx->diagnostic_read_seen, age, now - ctx->diagnostic_started_ms,
		(unsigned)requested, returned, ctx->diagnostic_read_bytes,
		ctx->diagnostic_positive_reads, ctx->diagnostic_zero_reads, max_gap);
	/* 16.11.2026 - The application may attach a cached transport snapshot.
	 * Do not notify on a nonterminal conflict or a normal TLS close. */
	if (!conflict && ctx->diagnostic_failure_callback != NULL) {
		ctx->diagnostic_failure_callback(ctx->diagnostic_failure_context, reason);
	}
}

#define SSLIO_DIAG_READ(ctx, len) sslio_diagnostic_read((ctx), (len))
#define SSLIO_DIAG_ZERO(ctx) (++(ctx)->diagnostic_zero_reads)
#define SSLIO_DIAG_FAIL(ctx, reason, requested, returned, conflict) \
	sslio_diagnostic_failure((ctx), (reason), (requested), (returned), (conflict))
#else
#define SSLIO_DIAG_READ(ctx, len) ((void)0)
#define SSLIO_DIAG_ZERO(ctx) ((void)0)
#define SSLIO_DIAG_FAIL(ctx, reason, requested, returned, conflict) ((void)0)
#endif


/* see bearssl_ssl.h */
void
br_sslio_init(br_sslio_context *ctx,
	br_ssl_engine_context *engine,
	int (*low_read)(void *read_context,
		unsigned char *data, size_t len),
	void *read_context,
	int (*low_write)(void *write_context,
		const unsigned char *data, size_t len),
	void *write_context)
{
	ctx->engine = engine;
	ctx->low_read = low_read;
	ctx->read_context = read_context;
	ctx->low_write = low_write;
	ctx->write_context = write_context;
	/* 16.11.2026 - Reset optional history when this I/O context is reused. */
#if defined(MS_OTA_DIAGNOSTICS)
	ctx->diagnostic_started_ms = sslio_diagnostic_now_ms();
	ctx->diagnostic_last_read_ms = 0;
	ctx->diagnostic_read_bytes = 0;
	ctx->diagnostic_positive_reads = 0;
	ctx->diagnostic_zero_reads = 0;
	ctx->diagnostic_max_read_gap_ms = 0;
	ctx->diagnostic_failure_callback = NULL;
	ctx->diagnostic_failure_context = NULL;
	ctx->diagnostic_read_seen = 0;
	ctx->diagnostic_failure_logged = 0;
	ctx->diagnostic_conflict_logged = 0;
#endif
}

/*
 * Run the engine, until the specified target state is achieved, or
 * an error occurs. The target state is SENDAPP, RECVAPP, or the
 * combination of both (the combination matches either). When a match is
 * achieved, this function returns 0. On error, it returns -1.
 */
static int
run_until(br_sslio_context *ctx, unsigned target)
{
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
//	log_printf("run_until >> target: %u\n", target);
//	esp_backtrace_print(100);
#endif

    xSemaphoreTake(msArduinoBearSslSemCriticalProcess, portMAX_DELAY);

	// <MS>
	unsigned long start_time = millis(); // Startzeit erfassen
    const unsigned long timeout = 5000;  // Timeout in Millisekunden (z. B. 5 Sekunden)
	int ms_timeout_counter = 0;

	for (;;) {
		unsigned state;
		state = br_ssl_engine_current_state(ctx->engine);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
//		log_printf("run_until - state: %u\n", state);		
#endif			
		if (state & BR_SSL_CLOSED) {
			/* 16.11.2026 - Identify engine failure observed before the target state. */
			SSLIO_DIAG_FAIL(ctx, "run/closed", 0, -1, 0);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
			log_printf("run_until << ***ERROR*** BR_SSL_CLOSED\n");		
#endif			

			xSemaphoreGive(msArduinoBearSslSemCriticalProcess);

			return -1;
		}

		/*
		 * If there is some record data to send, do it. This takes
		 * precedence over everything else.
		 */
		if (state & BR_SSL_SENDREC) {
			unsigned char *buf;
			size_t len;
			int wlen;

			buf = br_ssl_engine_sendrec_buf(ctx->engine, &len);
			wlen = ctx->low_write(ctx->write_context, buf, len);
			if (wlen < 0) {
				/*
				 * If we received a close_notify and we
				 * still send something, then we have our
				 * own response close_notify to send, and
				 * the peer is allowed by RFC 5246 not to
				 * wait for it.
				 */
				/* Always close the engine so br_sslio_close() can finish. */
				br_ssl_engine_fail(ctx->engine,
					ctx->engine->shutdown_recv ? BR_ERR_OK : BR_ERR_IO);
				/* 16.11.2026 - Keep verified close_notify shutdowns silent. */
				SSLIO_DIAG_FAIL(ctx, "run/low_write_negative", len, wlen, 0);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
				log_printf("run_until << ***ERROR*** wlen < 0\n");		
#endif				

				xSemaphoreGive(msArduinoBearSslSemCriticalProcess);

				return -1;
			}
			if (wlen > 0) {
				br_ssl_engine_sendrec_ack(ctx->engine, wlen);
			}
// <MS>
//			continue;
			ms_timeout_counter = 0;
			goto contx;
		}

		/*
		 * If we reached our target, then we are finished.
		 */
		if (state & target) {
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
			log_printf("run_until << ***OKAY*** target\n");		
#endif			

			xSemaphoreGive(msArduinoBearSslSemCriticalProcess);

			return 0;
		}

		/*
		 * If some application data must be read, and we did not
		 * exit, then this means that we are trying to write data,
		 * and that's not possible until the application data is
		 * read. This may happen if using a shared in/out buffer,
		 * and the underlying protocol is not strictly half-duplex.
		 * This is unrecoverable here, so we report an error.
		 */
		if (state & BR_SSL_RECVAPP) {
			/* 16.11.2026 - This refusal need not put the engine into failed state. */
			SSLIO_DIAG_FAIL(ctx, "run/target_conflict", 0, -1, 1);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
			log_printf("run_until << ***ERROR*** BR_SSL_RECVAPP\n");	
#endif				

			xSemaphoreGive(msArduinoBearSslSemCriticalProcess);

			return -1;
		}

		/*
		 * If we reached that point, then either we are trying
		 * to read data and there is some, or the engine is stuck
		 * until a new record is obtained.
		 */
		if (state & BR_SSL_RECVREC) {
			unsigned char *buf;
			size_t len;
			int rlen;

			buf = br_ssl_engine_recvrec_buf(ctx->engine, &len);
			rlen = ctx->low_read(ctx->read_context, buf, len);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
//			log_printf("run_until - rlen: %i\n", rlen);		
#endif			
			if (rlen < 0) {
				br_ssl_engine_fail(ctx->engine, BR_ERR_IO);
				/* 16.11.2026 - Report the exact transport callback failure site. */
				SSLIO_DIAG_FAIL(ctx, "run/low_read_negative", len, rlen, 0);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
				log_printf("run_until << ***ERROR*** rlen < 0\n");		
#endif				

				xSemaphoreGive(msArduinoBearSslSemCriticalProcess);

				return -1;
			}
			else
			if (rlen > 0) {
				/* 16.11.2026 - Timestamp ciphertext chunks, not application bytes. */
				SSLIO_DIAG_READ(ctx, (size_t)rlen);
				br_ssl_engine_recvrec_ack(ctx->engine, rlen);
				start_time = millis();
			}
			else {
				/* 16.11.2026 - Empty transport reads need no additional clock. */
				SSLIO_DIAG_ZERO(ctx);
				// <MS>
				if (millis() - start_time > timeout) {
					br_ssl_engine_fail(
						ctx->engine, BR_ERR_IO);
					/* 16.11.2026 - Preserve the existing five-second timeout. */
					SSLIO_DIAG_FAIL(ctx, "run/rx_no_progress_5s", len, rlen, 0);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
					log_printf("run_until << ***ERROR*** timeout\n");		
#endif

					xSemaphoreGive(msArduinoBearSslSemCriticalProcess);

					return -1;
				}
			}
// <MS>
//			continue;
			ms_timeout_counter = 0;
			goto contx;
		}

		/*
		 * We can reach that point if the target RECVAPP, and
		 * the state contains SENDAPP only. This may happen with
		 * a shared in/out buffer. In that case, we must flush
		 * the buffered data to "make room" for a new incoming
		 * record.
		 */
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
		log_printf("run_until - br_ssl_engine_flush()\n");		
#endif
		br_ssl_engine_flush(ctx->engine, 0);
		ms_timeout_counter++;
		if (ms_timeout_counter > 10) {
			// <MS>
			br_ssl_engine_fail(ctx->engine, BR_ERR_IO);
			/* 16.11.2026 - Distinguish local engine flush exhaustion from RX. */
			SSLIO_DIAG_FAIL(ctx, "run/flush_limit", 0, -1, 0);
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
			log_printf("run_until << ***ERROR*** br_ssl_engine_flush() - timeout\n");		
#endif

			xSemaphoreGive(msArduinoBearSslSemCriticalProcess);

			return -1;
		}

// <MS>
contx:
		delay(1);
	}
}

/* see bearssl_ssl.h */
int
br_sslio_read(br_sslio_context *ctx, void *dst, size_t len)
{
	unsigned char *buf;
	size_t alen;

	if (len == 0) {
		return 0;
	}
	if (run_until(ctx, BR_SSL_RECVAPP) < 0) {
#ifdef MS_ARDUINOBEARSSL_RUNUNTIL_LOGGING		
		log_printf("br_sslio_read << ***ERROR*** br_ssl_engine_flush() - timeout\n");		
		esp_backtrace_print(100);
#endif
		return -1;
	}
	buf = br_ssl_engine_recvapp_buf(ctx->engine, &alen);
	if (alen > len) {
		alen = len;
	}
	memcpy(dst, buf, alen);
	br_ssl_engine_recvapp_ack(ctx->engine, alen);
	return (int)alen;
}

/* see bearssl_ssl.h */
int
br_sslio_read_all(br_sslio_context *ctx, void *dst, size_t len)
{
	unsigned char *buf;

	buf = dst;
	while (len > 0) {
		int rlen;

		rlen = br_sslio_read(ctx, buf, len);
		if (rlen < 0) {
			return -1;
		}
		buf += rlen;
		len -= (size_t)rlen;
	}
	return 0;
}

#ifdef ARDUINO
int br_sslio_read_available(br_sslio_context *ctx)
{
	size_t alen;
	unsigned state = br_ssl_engine_current_state(ctx->engine);
	/* 16.11.2026 - A previous engine failure may be queried without run_until. */
	SSLIO_DIAG_FAIL(ctx, "available/engine_error", 0, -1, 0);

	if (state & BR_SSL_RECVREC) {
		unsigned char *buf;
		size_t len;
		int rlen;

		buf = br_ssl_engine_recvrec_buf(ctx->engine, &len);
		rlen = ctx->low_read(ctx->read_context, buf, len);
		if (rlen < 0) {
			br_ssl_engine_fail(ctx->engine, BR_ERR_IO);
			/* 16.11.2026 - available() can pull ciphertext before a read(). */
			SSLIO_DIAG_FAIL(ctx, "available/low_read_negative", len, rlen, 0);
			return -1;
		}
		if (rlen > 0) {
			/* 16.11.2026 - Preserve RX history across available/read calls. */
			SSLIO_DIAG_READ(ctx, (size_t)rlen);
			br_ssl_engine_recvrec_ack(ctx->engine, rlen);
			/* 16.11.2026 - Ciphertext acceptance can reveal crypto/protocol errors. */
			SSLIO_DIAG_FAIL(ctx, "available/engine_error", len, rlen, 0);
		} else {
			/* 16.11.2026 - Distinguish no ciphertext from incomplete plaintext. */
			SSLIO_DIAG_ZERO(ctx);
		}
	}
	br_ssl_engine_recvapp_buf(ctx->engine, &alen);
	return (int)alen;
}

int br_sslio_peek(br_sslio_context *ctx, void *dst, size_t len)
{
	unsigned char *buf;
	size_t alen;

	if (len == 0) {
		return 0;
	}
	unsigned state = br_ssl_engine_current_state(ctx->engine);
	/* 16.11.2026 - Report an existing error even when callers only peek. */
	SSLIO_DIAG_FAIL(ctx, "peek/engine_error", 0, -1, 0);

	if (state & BR_SSL_RECVREC) {
		unsigned char *buf;
		size_t len;
		int rlen;

		buf = br_ssl_engine_recvrec_buf(ctx->engine, &len);
		rlen = ctx->low_read(ctx->read_context, buf, len);
		if (rlen < 0) {
			br_ssl_engine_fail(ctx->engine, BR_ERR_IO);
			/* 16.11.2026 - Identify transport failures reached through peek(). */
			SSLIO_DIAG_FAIL(ctx, "peek/low_read_negative", len, rlen, 0);
			return -1;
		}
		if (rlen > 0) {
			/* 16.11.2026 - Peeking can receive another ciphertext chunk. */
			SSLIO_DIAG_READ(ctx, (size_t)rlen);
			br_ssl_engine_recvrec_ack(ctx->engine, rlen);
			/* 16.11.2026 - Peeking can also finish validation of an incoming record. */
			SSLIO_DIAG_FAIL(ctx, "peek/engine_error", len, rlen, 0);
		} else {
			/* 16.11.2026 - Keep peek's transport history consistent with read. */
			SSLIO_DIAG_ZERO(ctx);
		}
	}
	buf = br_ssl_engine_recvapp_buf(ctx->engine, &alen);
	if (alen > len) {
		alen = len;
	}
	memcpy(dst, buf, alen);
	return (int)alen;
}
#endif

/* see bearssl_ssl.h */
int
br_sslio_write(br_sslio_context *ctx, const void *src, size_t len)
{
	unsigned char *buf;
	size_t alen;

	if (len == 0) {
		return 0;
	}
	if (run_until(ctx, BR_SSL_SENDAPP) < 0) {
		return -1;
	}
	buf = br_ssl_engine_sendapp_buf(ctx->engine, &alen);
	if (alen > len) {
		alen = len;
	}
	memcpy(buf, src, alen);
	br_ssl_engine_sendapp_ack(ctx->engine, alen);
	return (int)alen;
}

/* see bearssl_ssl.h */
int
br_sslio_write_all(br_sslio_context *ctx, const void *src, size_t len)
{
	const unsigned char *buf;

	buf = src;
	while (len > 0) {
		int wlen;

		wlen = br_sslio_write(ctx, buf, len);
		if (wlen < 0) {
			return -1;
		}
		buf += wlen;
		len -= (size_t)wlen;
	}
	return 0;
}

/* see bearssl_ssl.h */
int
br_sslio_flush(br_sslio_context *ctx)
{
	/*
	 * We trigger a flush. We know the data is gone when there is
	 * no longer any record data to send, and we can either read
	 * or write application data. The call to run_until() does the
	 * job because it ensures that any assembled record data is
	 * first sent down the wire before considering anything else.
	 */
	br_ssl_engine_flush(ctx->engine, 0);
	return run_until(ctx, BR_SSL_SENDAPP | BR_SSL_RECVAPP);
}

/* see bearssl_ssl.h */
int
br_sslio_close(br_sslio_context *ctx)
{
	// <MS>
#if defined(MS_ARDUINOBEARSSL_LOGGING) && defined(MS_LOGGER_ON)
	log_printf("%s", "br_sslio_close: >>\n");
//	esp_backtrace_print(100);
#endif

	br_ssl_engine_close(ctx->engine);
	while (br_ssl_engine_current_state(ctx->engine) != BR_SSL_CLOSED) {
		/*
		 * Discard any incoming application data.
		 */
		size_t len;

#if defined(MS_ARDUINOBEARSSL_LOGGING) && defined(MS_LOGGER_ON)
		log_printf("%s", "br_sslio_close: call run_until() ...\n");
		int rc =
#endif		
		run_until(ctx, BR_SSL_RECVAPP);
#if defined(MS_ARDUINOBEARSSL_LOGGING) && defined(MS_LOGGER_ON)
		log_printf("br_sslio_close: run_until() returned %i\n", rc);
#endif		
		if (br_ssl_engine_recvapp_buf(ctx->engine, &len) != NULL) {
			br_ssl_engine_recvapp_ack(ctx->engine, len);
		}
	}
#if defined(MS_ARDUINOBEARSSL_LOGGING) && defined(MS_LOGGER_ON)
	log_printf("%s", "br_sslio_close: <<\n");
#endif	
	return br_ssl_engine_last_error(ctx->engine) == BR_ERR_OK;
}
