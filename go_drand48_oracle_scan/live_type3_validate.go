package main

import (
    "bufio"
    "bytes"
    "encoding/hex"
    "errors"
    "flag"
    "fmt"
    "math/rand"
    "os"
    "os/exec"
    "runtime"
    "strings"
    "time"
)

const (
    WBYTES = 5
    BBYTES = 10
    ROUNDS = 26
)

type ParsedInput struct {
    Kind          string
    Type          int
    HeaderBadgeID *int
    ChecksumOK    *bool
    Ciphertext10  []byte
    Raw           []byte
}

func cleanHex(s string) string {
    s = strings.TrimSpace(s)
    s = strings.ReplaceAll(s, "0x", "")
    s = strings.ReplaceAll(s, "0X", "")
    var b strings.Builder
    for _, ch := range s {
        if ('0' <= ch && ch <= '9') || ('a' <= ch && ch <= 'f') || ('A' <= ch && ch <= 'F') {
            b.WriteRune(ch)
        }
    }
    return strings.ToLower(b.String())
}

func sumBytes(b []byte) int {
    total := 0
    for _, x := range b {
        total += int(x)
    }
    return total
}

func checksumZero(buf []byte) bool {
    return (sumBytes(buf) & 0xFF) == 0
}

func typeDataLen(ptype int) (int, bool) {
    m := map[int]int{
        0x00: 0, 0x01: 0, 0x02: 134, 0x03: 10, 0x04: 10,
        0x05: 2, 0x06: 2, 0x07: 3, 0x08: 1, 0x09: 4,
        0x0A: 2, 0x0B: 2, 0x0C: 0,
    }
    v, ok := m[ptype]
    return v, ok
}

func parseSmashOrCipher(hexish string, wantType int) (ParsedInput, error) {
    s := cleanHex(hexish)
    raw, err := hex.DecodeString(s)
    if err != nil {
        return ParsedInput{}, err
    }
    hdr := []byte("Smash?")
    if len(raw) >= 6 && bytes.Equal(raw[:6], hdr) {
        if len(raw) < 11 {
            return ParsedInput{}, fmt.Errorf("Smash frame too short")
        }
        ptype := int(raw[7])
        bid := int(raw[8])<<8 | int(raw[9])
        dlen, ok := typeDataLen(ptype)
        if !ok {
            return ParsedInput{}, fmt.Errorf("unknown Smash packet type 0x%02x", ptype)
        }
        expect := 11 + dlen
        if len(raw) != expect {
            return ParsedInput{}, fmt.Errorf("Smash frame length mismatch: got %d expected %d", len(raw), expect)
        }
        if wantType >= 0 && ptype != wantType {
            return ParsedInput{}, fmt.Errorf("expected type 0x%02x, got 0x%02x", wantType, ptype)
        }
        chk := checksumZero(raw)
        out := ParsedInput{
            Kind:          "smash",
            Type:          ptype,
            HeaderBadgeID: &bid,
            ChecksumOK:    &chk,
            Raw:           raw,
        }
        if dlen == 10 {
            out.Ciphertext10 = append([]byte(nil), raw[10:20]...)
        }
        return out, nil
    }
    if len(raw) == 10 {
        return ParsedInput{Kind: "ciphertext10", Type: wantType, Ciphertext10: raw, Raw: raw}, nil
    }
    return ParsedInput{}, fmt.Errorf("input must be a full Smash frame or bare 10-byte ciphertext")
}

func decryptExactBytes(keyBytes []byte, block []byte) ([]byte, error) {
    if len(block) != BBYTES {
        return nil, fmt.Errorf("cipher block must be exactly 10 bytes")
    }
    if len(keyBytes) != 10 {
        return nil, fmt.Errorf("key must be 10 bytes")
    }
    key := append([]byte(nil), keyBytes...)
    crypt := append([]byte(nil), block...)

    for byteI := 0; byteI < ROUNDS; byteI++ {
        byteK0 := key[WBYTES]
        int32AK := 0
        for byteJ := 0; byteJ < WBYTES-1; byteJ++ {
            int32AK += int(key[byteJ]) + int(key[byteJ+1+WBYTES])
            key[byteJ+WBYTES] = byte(int32AK & 0xFF)
            int32AK >>= 8
        }
        int32AK += int(key[WBYTES-1]) + int(byteK0)
        key[WBYTES-1+WBYTES] = byte(int32AK & 0xFF)
        key[WBYTES] = byte((int(key[WBYTES]) ^ byteI) & 0xFF)
        byteK0 = key[WBYTES-1]
        for byteJ := WBYTES - 1; byteJ > 0; byteJ-- {
            key[byteJ] = byte((((int(key[byteJ]) << 3) | (int(key[byteJ-1]) >> 5)) ^ int(key[byteJ+WBYTES])) & 0xFF)
        }
        key[0] = byte((((int(key[0]) << 3) | (int(byteK0) >> 5)) ^ int(key[WBYTES])) & 0xFF)
    }

    for byteI := ROUNDS - 1; byteI >= 0; byteI-- {
        for byteJ := 0; byteJ < WBYTES; byteJ++ {
            key[byteJ] ^= key[byteJ+WBYTES]
            crypt[byteJ] ^= crypt[byteJ+WBYTES]
        }
        byteK0 := key[0]
        byteC0 := crypt[0]
        for byteJ := 0; byteJ < WBYTES-1; byteJ++ {
            key[byteJ] = byte(((int(key[byteJ]) >> 3) | (int(key[byteJ+1]) << 5)) & 0xFF)
            crypt[byteJ] = byte(((int(crypt[byteJ]) >> 3) | (int(crypt[byteJ+1]) << 5)) & 0xFF)
        }
        key[WBYTES-1] = byte(((int(key[WBYTES-1]) >> 3) | (int(byteK0) << 5)) & 0xFF)
        crypt[WBYTES-1] = byte(((int(crypt[WBYTES-1]) >> 3) | (int(byteC0) << 5)) & 0xFF)
        key[WBYTES] = byte((int(key[WBYTES]) ^ byteI) & 0xFF)
        for byteJ := 0; byteJ < WBYTES; byteJ++ {
            crypt[byteJ+WBYTES] = byte((int(crypt[byteJ+WBYTES]) ^ int(key[byteJ])) & 0xFF)
        }
        int32AK := 0
        int32AC := 0
        for byteJ := 0; byteJ < WBYTES; byteJ++ {
            int32AK += int(key[byteJ+WBYTES]) - int(key[byteJ])
            key[byteJ+WBYTES] = byte(int32AK & 0xFF)
            int32AK >>= 8
            int32AC += int(crypt[byteJ+WBYTES]) - int(crypt[byteJ])
            crypt[byteJ+WBYTES] = byte(int32AC & 0xFF)
            int32AC >>= 8
        }
        byteK0 = key[WBYTES-1+WBYTES]
        byteC0 = crypt[WBYTES-1+WBYTES]
        for byteJ := WBYTES - 1; byteJ > 0; byteJ-- {
            key[byteJ+WBYTES] = key[byteJ-1+WBYTES]
            crypt[byteJ+WBYTES] = crypt[byteJ-1+WBYTES]
        }
        key[WBYTES] = byteK0
        crypt[WBYTES] = byteC0
    }

    return crypt, nil
}

func encryptExactBytes(keyBytes []byte, block []byte) ([]byte, error) {
    if len(block) != BBYTES || len(keyBytes) != 10 {
        return nil, fmt.Errorf("key and block must be 10 bytes")
    }
    key := append([]byte(nil), keyBytes...)
    crypt := append([]byte(nil), block...)

    for byteI := 0; byteI < ROUNDS; byteI++ {
        byteC0 := crypt[WBYTES]
        byteK0 := key[WBYTES]
        int32AC := 0
        int32AK := 0

        for byteJ := 0; byteJ < WBYTES-1; byteJ++ {
            int32AC += int(crypt[byteJ]) + int(crypt[byteJ+1+WBYTES])
            crypt[byteJ+WBYTES] = byte((int32AC ^ int(key[byteJ])) & 0xFF)
            int32AC >>= 8

            int32AK += int(key[byteJ]) + int(key[byteJ+1+WBYTES])
            key[byteJ+WBYTES] = byte(int32AK & 0xFF)
            int32AK >>= 8
        }

        int32AC += int(crypt[WBYTES-1]) + int(byteC0)
        crypt[WBYTES-1+WBYTES] = byte((int32AC ^ int(key[WBYTES-1])) & 0xFF)

        int32AK += int(key[WBYTES-1]) + int(byteK0)
        key[WBYTES-1+WBYTES] = byte(int32AK & 0xFF)
        key[WBYTES] = byte((int(key[WBYTES]) ^ byteI) & 0xFF)

        byteC0 = crypt[WBYTES-1]
        byteK0 = key[WBYTES-1]
        for byteJ := WBYTES - 1; byteJ > 0; byteJ-- {
            crypt[byteJ] = byte((((int(crypt[byteJ]) << 3) | (int(crypt[byteJ-1]) >> 5)) ^ int(crypt[byteJ+WBYTES])) & 0xFF)
            key[byteJ] = byte((((int(key[byteJ]) << 3) | (int(key[byteJ-1]) >> 5)) ^ int(key[byteJ+WBYTES])) & 0xFF)
        }
        crypt[0] = byte((((int(crypt[0]) << 3) | (int(byteC0) >> 5)) ^ int(crypt[WBYTES])) & 0xFF)
        key[0] = byte((((int(key[0]) << 3) | (int(byteK0) >> 5)) ^ int(key[WBYTES])) & 0xFF)
    }

    return crypt, nil
}

func buildSmashFrame(status byte, ptype byte, badgeID uint16, data []byte) ([]byte, error) {
    dlen, ok := typeDataLen(int(ptype))
    if !ok {
        return nil, fmt.Errorf("unknown type 0x%02x", ptype)
    }
    if len(data) != dlen {
        return nil, fmt.Errorf("type 0x%02x requires %d data bytes", ptype, dlen)
    }
    frame := append([]byte("Smash?"), status, ptype, byte(badgeID>>8), byte(badgeID))
    frame = append(frame, data...)
    frame = append(frame, byte((-sumBytes(frame))&0xFF))
    return frame, nil
}

func makeType3Plaintext(badgeID uint16, badgeOnce []byte, requestedCredits []byte, vendoOnce []byte) ([]byte, error) {
    if len(badgeOnce) != 2 || len(requestedCredits) != 2 || len(vendoOnce) != 3 {
        return nil, fmt.Errorf("bad field lengths for type3 plaintext")
    }
    pt := []byte{byte(badgeID >> 8), byte(badgeID)}
    pt = append(pt, badgeOnce...)
    pt = append(pt, requestedCredits...)
    pt = append(pt, vendoOnce...)
    pt = append(pt, byte((-sumBytes(pt))&0xFF))
    return pt, nil
}

func parseType2Dump(frame []byte) (badgeID uint16, once []byte, err error) {
    p, err := parseSmashOrCipher(hex.EncodeToString(frame), 0x02)
    if err != nil {
        return 0, nil, err
    }
    data := p.Raw[10 : len(p.Raw)-1]
    if len(data) != 134 {
        return 0, nil, fmt.Errorf("type2 data wrong length")
    }
    badgeID = uint16(data[2])<<8 | uint16(data[3])
    once = append([]byte(nil), data[136:138]...)
    return badgeID, once, nil
}

func configureSerial(port string, baud int) error {
    var args []string
    switch runtime.GOOS {
    case "darwin":
        args = []string{"-f", port, fmt.Sprintf("%d", baud), "cs8", "-cstopb", "-parenb", "raw", "-echo"}
    default:
        args = []string{"-F", port, fmt.Sprintf("%d", baud), "cs8", "-cstopb", "-parenb", "raw", "-echo"}
    }
    cmd := exec.Command("stty", args...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("stty failed: %v: %s", err, strings.TrimSpace(string(out)))
    }
    return nil
}

func openSerialRaw(port string, baud int) (*os.File, error) {
    if err := configureSerial(port, baud); err != nil {
        return nil, err
    }
    return os.OpenFile(port, os.O_RDWR, 0)
}

func writeAll(f *os.File, b []byte) error {
    off := 0
    for off < len(b) {
        n, err := f.Write(b[off:])
        if err != nil {
            return err
        }
        off += n
    }
    return nil
}

func drainSerial(f *os.File, quietFor time.Duration) {
    tmp := make([]byte, 256)
    deadline := time.Now().Add(quietFor)
    for {
        _ = f.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
        n, err := f.Read(tmp)
        if err != nil {
            var pe interface{ Timeout() bool }
            if os.IsTimeout(err) || (errors.As(err, &pe) && pe.Timeout()) {
                if time.Now().After(deadline) {
                    return
                }
                continue
            }
            return
        }
        if n > 0 {
            deadline = time.Now().Add(quietFor)
        } else if time.Now().After(deadline) {
            return
        }
    }
}

func readNextSmashFrame(f *os.File, timeout time.Duration, wantTypes map[byte]bool) ([]byte, error) {
    deadline := time.Now().Add(timeout)
    var buf []byte
    tmp := make([]byte, 256)
    _ = f.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
    for time.Now().Before(deadline) {
        n, err := f.Read(tmp)
        if err != nil {
            if os.IsTimeout(err) {
                // continue
            } else {
                var pe interface{ Timeout() bool }
                if errors.As(err, &pe) && pe.Timeout() {
                    // continue
                } else {
                    return nil, err
                }
            }
        }
        if n > 0 {
            buf = append(buf, tmp[:n]...)
            for {
                idx := bytes.Index(buf, []byte("Smash?"))
                if idx < 0 {
                    if len(buf) > 5 {
                        buf = append([]byte(nil), buf[len(buf)-5:]...)
                    }
                    break
                }
                if len(buf[idx:]) < 11 {
                    if idx > 0 {
                        buf = append([]byte(nil), buf[idx:]...)
                    }
                    break
                }
                ptype := buf[idx+7]
                dlen, ok := typeDataLen(int(ptype))
                if !ok {
                    buf = append([]byte(nil), buf[idx+1:]...)
                    continue
                }
                total := 11 + dlen
                if len(buf[idx:]) < total {
                    if idx > 0 {
                        buf = append([]byte(nil), buf[idx:]...)
                    }
                    break
                }
                frame := append([]byte(nil), buf[idx:idx+total]...)
                buf = append([]byte(nil), buf[idx+total:]...)
                if !checksumZero(frame) {
                    continue
                }
                if wantTypes == nil || wantTypes[ptype] {
                    return frame, nil
                }
            }
        }
        _ = f.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
    }
    return nil, fmt.Errorf("timeout waiting for Smash frame")
}

func defaultVonce() []byte {
    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    return []byte{byte(r.Intn(255)), byte(r.Intn(255)), byte(r.Intn(255))}
}

func selfTest() error {
    key, _ := hex.DecodeString("e92fd2287edca7e2b18c")
    once, _ := hex.DecodeString("15c5")
    req, _ := hex.DecodeString("0002")
    vonce, _ := hex.DecodeString("474bfe")
    pt, err := makeType3Plaintext(0x020d, once, req, vonce)
    if err != nil { return err }
    ct3, err := encryptExactBytes(key, pt)
    if err != nil { return err }
    if got := hex.EncodeToString(ct3); got != "343c14417c3acf6754ab" {
        return fmt.Errorf("type3 ciphertext mismatch: %s", got)
    }
    t4ct, _ := hex.DecodeString("0e79e0b7446e29738e29")
    p4, err := decryptExactBytes(key, t4ct)
    if err != nil { return err }
    if got := hex.EncodeToString(p4); got != "020d474bfe00021bf54f" {
        return fmt.Errorf("type4 plaintext mismatch: %s", got)
    }
    return nil
}

func main() {
    port := flag.String("port", "", "serial port, e.g. /dev/cu.usbserial-TG1101910")
    keyHex := flag.String("key-hex", "", "10-byte candidate key hex")
    type3Hex := flag.String("type3-hex", "", "optional captured type3 frame to infer badge id and requested credits")
    badgeIDStr := flag.String("badge-id", "", "badge id override, e.g. 0x020d")
    requestedCreditsHex := flag.String("requested-credits", "", "2-byte requested credits, e.g. 0x0002")
    vonceHex := flag.String("vonce-hex", "", "optional 3-byte vendo nonce override")
    baud := flag.Int("baud", 4800, "serial baud rate")
    dumpTimeout := flag.Duration("dump-timeout", 5*time.Second, "timeout for dump response")
    cryptoTimeout := flag.Duration("crypto-timeout", 5*time.Second, "timeout for type4 response")
    resetNulls := flag.Bool("reset-nulls", false, "send 20 null bytes before dump")
    endNormal := flag.Bool("send-end-normal", false, "send the end-of-normal social ping before dump")
    settleMs := flag.Int("settle-ms", 750, "delay after reset/end-normal before dump request")
    interCommandMs := flag.Int("inter-command-ms", 300, "delay between serial commands")
    dumpRetries := flag.Int("dump-retries", 3, "number of dump request attempts")
    selftest := flag.Bool("self-test", false, "run crypto self-test and exit")
    flag.Parse()

    if *selftest {
        if err := selfTest(); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        fmt.Println("self-test ok")
        return
    }

    if *port == "" || *keyHex == "" {
        fmt.Fprintln(os.Stderr, "--port and --key-hex are required")
        os.Exit(2)
    }

    keyBytes, err := hex.DecodeString(cleanHex(*keyHex))
    if err != nil || len(keyBytes) != 10 {
        fmt.Fprintln(os.Stderr, "--key-hex must be exactly 10 bytes / 20 hex chars")
        os.Exit(2)
    }

    var badgeID uint16
    var haveBadge bool
    var req []byte
    if *type3Hex != "" {
        t3, err := parseSmashOrCipher(*type3Hex, 0x03)
        if err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(2)
        }
        p3, err := decryptExactBytes(keyBytes, t3.Ciphertext10)
        if err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(2)
        }
        badgeID = uint16(p3[0])<<8 | uint16(p3[1])
        haveBadge = true
        req = append([]byte(nil), p3[4:6]...)
        fmt.Printf("captured type3 decrypted: %s\n", hex.EncodeToString(p3))
        fmt.Printf("captured badge_id=0x%04x requested_credits=0x%s captured_once=0x%s\n", badgeID, hex.EncodeToString(req), hex.EncodeToString(p3[2:4]))
    }
    if *badgeIDStr != "" {
        var x int
        _, err := fmt.Sscanf(*badgeIDStr, "%v", &x)
        if err != nil {
            x64, e2 := parseIntAny(*badgeIDStr)
            if e2 != nil { fmt.Fprintln(os.Stderr, e2); os.Exit(2) }
            x = int(x64)
        }
        badgeID = uint16(x)
        haveBadge = true
    }
    if *requestedCreditsHex != "" {
        req, err = hex.DecodeString(cleanHex(*requestedCreditsHex))
        if err != nil || len(req) != 2 {
            fmt.Fprintln(os.Stderr, "--requested-credits must be exactly 2 bytes")
            os.Exit(2)
        }
    }
    if !haveBadge || len(req) != 2 {
        fmt.Fprintln(os.Stderr, "need badge id and requested credits; either provide --type3-hex or explicit --badge-id and --requested-credits")
        os.Exit(2)
    }

    f, err := openSerialRaw(*port, *baud)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    defer f.Close()

    drainSerial(f, 250*time.Millisecond)

    if *resetNulls {
        zeros := make([]byte, 20)
        if err := writeAll(f, zeros); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        time.Sleep(time.Duration(*interCommandMs) * time.Millisecond)
        drainSerial(f, 150*time.Millisecond)
        fmt.Println("sent 20 null bytes")
    }

    if *endNormal {
        endFrame := append([]byte("Smash?"), 0x00, 0x00, 0x01, 0xFF, 0xC5)
        if err := writeAll(f, endFrame); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        time.Sleep(time.Duration(*interCommandMs) * time.Millisecond)
        drainSerial(f, 150*time.Millisecond)
        fmt.Println("sent end-of-normal social ping")
    }

    if *resetNulls || *endNormal {
        time.Sleep(time.Duration(*settleMs) * time.Millisecond)
    }

    dumpReq, _ := buildSmashFrame(0x00, 0x01, 0x02ff, nil)
    var dumpFrame []byte
    for attempt := 1; attempt <= *dumpRetries; attempt++ {
        drainSerial(f, 100*time.Millisecond)
        if err := writeAll(f, dumpReq); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        fmt.Printf("dump request[%d/%d]: %s\n", attempt, *dumpRetries, hex.EncodeToString(dumpReq))

        dumpFrame, err = readNextSmashFrame(f, *dumpTimeout, map[byte]bool{0x02: true})
        if err == nil {
            break
        }
        if attempt < *dumpRetries {
            fmt.Printf("dump attempt %d timed out, retrying...\n", attempt)

            time.Sleep(time.Duration(*settleMs) * time.Millisecond)
        }
    }
    if err != nil {
        fmt.Fprintln(os.Stderr, "dump failed:", err)
        os.Exit(1)
    }
    liveBadgeID, liveOnce, err := parseType2Dump(dumpFrame)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    fmt.Printf("dump response: %s\n", hex.EncodeToString(dumpFrame))
    fmt.Printf("live dump badge_id=0x%04x once=0x%s\n", liveBadgeID, hex.EncodeToString(liveOnce))
    if liveBadgeID != badgeID {
        fmt.Fprintf(os.Stderr, "badge id mismatch: live dump 0x%04x vs candidate 0x%04x\n", liveBadgeID, badgeID)
        os.Exit(1)
    }

    var vonce []byte
    if *vonceHex != "" {
        vonce, err = hex.DecodeString(cleanHex(*vonceHex))
        if err != nil || len(vonce) != 3 {
            fmt.Fprintln(os.Stderr, "--vonce-hex must be exactly 3 bytes")
            os.Exit(2)
        }
    } else {
        vonce = defaultVonce()
    }

    p3, err := makeType3Plaintext(badgeID, liveOnce, req, vonce)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    ct3, err := encryptExactBytes(keyBytes, p3)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    type3Frame, _ := buildSmashFrame(0x00, 0x03, 0x02ff, ct3)
    fmt.Printf("forged type3 plaintext: %s\n", hex.EncodeToString(p3))
    fmt.Printf("forged type3 frame: %s\n", hex.EncodeToString(type3Frame))
    drainSerial(f, 100*time.Millisecond)
    if err := writeAll(f, type3Frame); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    time.Sleep(time.Duration(*interCommandMs) * time.Millisecond)

    type4Frame, err := readNextSmashFrame(f, *cryptoTimeout, map[byte]bool{0x04: true})
    if err != nil {
        fmt.Fprintln(os.Stderr, "type4 wait failed:", err)
        os.Exit(1)
    }
    p4in, err := parseSmashOrCipher(hex.EncodeToString(type4Frame), 0x04)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    p4, err := decryptExactBytes(keyBytes, p4in.Ciphertext10)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    fmt.Printf("type4 frame: %s\n", hex.EncodeToString(type4Frame))
    fmt.Printf("type4 plaintext: %s\n", hex.EncodeToString(p4))

    ok := checksumZero(p4) &&
        uint16(p4[0])<<8|uint16(p4[1]) == badgeID &&
        bytes.Equal(p4[2:5], vonce) &&
        bytes.Equal(p4[5:7], req) &&
        p4[7] != liveOnce[0] && p4[8] != liveOnce[1]
    if ok {
        fmt.Println("live confirmation ok")
    } else {
        fmt.Println("live confirmation failed")
        os.Exit(1)
    }
}

func parseIntAny(s string) (uint64, error) {
    s = strings.TrimSpace(s)
    var base int = 10
    if strings.HasPrefix(strings.ToLower(s), "0x") {
        base = 16
        s = s[2:]
    }
    var x uint64
    for _, ch := range s {
        var v int
        switch {
        case ch >= '0' && ch <= '9':
            v = int(ch - '0')
        case ch >= 'a' && ch <= 'f':
            v = 10 + int(ch-'a')
        case ch >= 'A' && ch <= 'F':
            v = 10 + int(ch-'A')
        default:
            return 0, fmt.Errorf("bad integer: %q", s)
        }
        if v >= base {
            return 0, fmt.Errorf("bad integer: %q", s)
        }
        x = x*uint64(base) + uint64(v)
    }
    return x, nil
}

func init() {
    rand.Seed(time.Now().UnixNano())
    // Encourage line-buffer-free behavior on some systems when attached to TTY.
    if fi, _ := os.Stdout.Stat(); (fi.Mode() & os.ModeCharDevice) != 0 {
        w := bufio.NewWriter(os.Stdout)
        _ = w
    }
}
