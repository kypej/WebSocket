package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
)

func main() {
	http.HandleFunc("/", wsHandler)
	http.ListenAndServe(":8000", nil)

}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	// проверяем заголовки
	if r.Header.Get("Upgrade") != "websocket" {
		return
	}
	if r.Header.Get("Connection") != "Upgrade" {
		return
	}
	k := r.Header.Get("Sec-Websocket-Key")
	if k == "" {
		return
	}

	// вычисляем ответ
	sum := k + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash := sha1.Sum([]byte(sum))
	str := base64.StdEncoding.EncodeToString(hash[:])

	// Берем под контроль соединение https://pkg.go.dev/net/http#Hijacker
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// формируем ответ
	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	bufrw.WriteString("Upgrade: websocket\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString("Sec-Websocket-Accept: " + str + "\r\n\r\n")
	bufrw.Flush()

	// сообщение состоит из одного или нескольких фреймов
	var message []byte
	for {
		// заголовок состоит из 2 — 14 байт
		buf := make([]byte, 2, 12)
		// читаем первые 2 байта
		_, err := bufrw.Read(buf)
		if err != nil {
			return
		}

		finBit := buf[0]       // фрагментированное ли сообщение 129
		finBit = finBit >> 7   // фрагментированное ли сообщение
		opCode := buf[0] & 0xf // опкод

		maskBit := buf[1]      // замаскированы ли данные 141
		maskBit = maskBit >> 7 // замаскированы ли данные

		// оставшийся размер заголовка
		extra := 0
		if maskBit == 1 {
			extra += 4 // +4 байта маскировочный ключ
		}

		size := uint64(buf[1] & 0x7f)
		if size == 126 {
			extra += 2 // +2 байта размер данных
		} else if size == 127 {
			extra += 8 // +8 байт размер данных
		}

		if extra > 0 {
			// читаем остаток заголовка extra <= 12
			buf = buf[:extra]
			_, err = bufrw.Read(buf)
			if err != nil {
				return
			}

			if size == 126 {
				size = uint64(binary.BigEndian.Uint16(buf[:2]))
				buf = buf[2:] // подвинем начало буфера на 2 байта
			} else if size == 127 {
				size = binary.BigEndian.Uint64(buf[:8])
				buf = buf[8:] // подвинем начало буфера на 8 байт
			}
		}

		// маскировочный ключ
		var mask []byte
		if maskBit == 1 {
			// остаток заголовка, последние 4 байта
			mask = buf
		}

		// данные фрейма
		payload := make([]byte, int(size))
		// читаем полностью и ровно size байт
		_, err = io.ReadFull(bufrw, payload)
		if err != nil {
			return
		}

		// размаскировываем данные с помощью XOR
		if maskBit == 1 {
			for i := 0; i < len(payload); i++ {
				payload[i] ^= mask[i%4]
			}
		}

		// складываем фрагменты сообщения
		message = append(message, payload...)

		if opCode == 8 { // фрейм закрытия
			return
		} else if finBit == 1 { // конец сообщения
			fmt.Println(string(message))
		}

		buf = make([]byte, 2)
		buf[0] |= opCode

		if finBit == 1 {
			buf[0] |= 0x80
		}

		if size < 126 {
			buf[1] |= byte(size)
		} else if size < 1<<16 {
			buf[1] |= 126
			sizze := make([]byte, 2)
			binary.BigEndian.PutUint16(sizze, uint16(size))
			buf = append(buf, sizze...)
		} else {
			buf[1] |= 127
			sizze := make([]byte, 8)
			binary.BigEndian.PutUint64(sizze, size)
			buf = append(buf, sizze...)
		}
		buf = append(buf, message...)

		bufrw.Write(buf)
		bufrw.Flush()

		if opCode == 8 {
			fmt.Println(buf)
			return
		} else if finBit == 1 {
			fmt.Println(string(message))
			message = message[:0]
		}
	}
}
