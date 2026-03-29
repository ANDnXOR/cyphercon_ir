package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MASK48 uint64 = (1 << 48) - 1
	A48    uint64 = 0x5DEECE66D
	C48    uint64 = 0xB

	WBYTES = 5
	BBYTES = 10
	ROUNDS = 26

	// Generic sweeps usually only need the first handful of sequential keys.
	DEFAULT_KEYS_PER_SEED = 20
)

type ParsedInput struct {
	Kind          string `json:"kind"`
	Type          int    `json:"type"`
	HeaderBadgeID *int   `json:"header_badge_id"`
	ChecksumOK    *bool  `json:"checksum_ok"`
	Ciphertext10  []byte `json:"-"`
	RawHex        string `json:"raw_hex"`
}

type Candidate struct {
	Seed32           uint32   `json:"seed32"`
	KeyIndex         int      `json:"key_index"`
	KeyHex           string   `json:"key_hex"`
	Score            int      `json:"score"`
	Reasons          []string `json:"reasons"`
	StrictMatch      bool     `json:"strict_match"`
	Type3PlainHex    string   `json:"type3_plain_hex"`
	Type4PlainHex    string   `json:"type4_plain_hex"`
	BadgeIDFromPlain int      `json:"badge_id_from_plain"`
	RequestedCredits string   `json:"requested_credits_hex"`
	VendoOnceHex     string   `json:"vendo_once_hex"`
}

type Report struct {
	Inputs struct {
		Model               string `json:"model"`
		Type3Kind           string `json:"type3_kind"`
		Type4Kind           string `json:"type4_kind"`
		Type4HeaderBadgeID  *int   `json:"type4_header_badge_id"`
		Type3ChecksumOK     *bool  `json:"type3_checksum_ok"`
		Type4ChecksumOK     *bool  `json:"type4_checksum_ok"`
		Type3Only           bool   `json:"type3_only,omitempty"`
		DumpOnceHex         string `json:"dump_once_hex"`
		BadgeIDHint         *int   `json:"badge_id_hint"`
		RequestedCreditsHex string `json:"requested_credits_hex,omitempty"`
		Seed32s             string `json:"seed32s,omitempty"`
		StartSeed32         string `json:"start_seed32,omitempty"`
		EndSeed32           string `json:"end_seed32,omitempty"`
		Descending          bool   `json:"descending,omitempty"`
		StopOnFirstStrict   bool   `json:"stop_on_first_strict,omitempty"`
		KeysPerSeed         int    `json:"keys_per_seed"`
		Workers             int    `json:"workers"`
	} `json:"inputs"`
	ProcessedSeeds      uint64      `json:"processed_seeds"`
	ProcessedCandidates uint64      `json:"processed_candidates"`
	Stage1Survivors     uint64      `json:"stage1_survivors"`
	StrictMatchCount    int         `json:"strict_match_count"`
	StrictMatches       []Candidate `json:"strict_matches"`
	Best                *Candidate  `json:"best"`
	Top                 []Candidate `json:"top"`
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
	if len(raw) >= 6 && string(raw[:6]) == string(hdr) {
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
		chk := (sumBytes(raw) & 0xFF) == 0
		return ParsedInput{
			Kind:          "smash",
			Type:          ptype,
			HeaderBadgeID: &bid,
			ChecksumOK:    &chk,
			Ciphertext10:  raw[10 : len(raw)-1],
			RawHex:        hex.EncodeToString(raw),
		}, nil
	}
	if len(raw) == 10 {
		return ParsedInput{
			Kind:          "ciphertext10",
			Type:          wantType,
			HeaderBadgeID: nil,
			ChecksumOK:    nil,
			Ciphertext10:  raw,
			RawHex:        hex.EncodeToString(raw),
		}, nil
	}
	return ParsedInput{}, fmt.Errorf("input must be a full Smash frame or bare 10-byte ciphertext")
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

func eachDrand48Key(seed32 uint32, nkeys int, fn func(keyIndex int, keyBytes []byte)) {
	x := (uint64(seed32) << 16) + 0x330E
	key := make([]byte, 10)
	for keyIndex := 0; keyIndex < nkeys; keyIndex++ {
		for i := 0; i < 10; i++ {
			x = (A48*x + C48) & MASK48
			key[i] = byte((x * 255) >> 48)
		}
		fn(keyIndex, key)
	}
}

func decryptExactBytes(keyBytes []byte, block []byte) ([]byte, error) {
	if len(block) != BBYTES {
		return nil, fmt.Errorf("cipher block must be exactly 10 bytes")
	}
	if len(keyBytes) != 10 {
		return nil, fmt.Errorf("key must be 10 bytes")
	}
	key := make([]byte, 10)
	copy(key, keyBytes)
	crypt := make([]byte, 10)
	copy(crypt, block)

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

func scoreFromPlaintexts(p3, p4, dumpOnce []byte, badgeIDHint *int, t4HeaderBadgeID *int) Candidate {
	score := 0
	reasons := []string{}

	p3Checksum := checksumZero(p3)
	if p3Checksum {
		score += 2
		reasons = append(reasons, "p3 checksum ok")
	}
	p4Checksum := checksumZero(p4)
	if p4Checksum {
		score += 2
		reasons = append(reasons, "p4 checksum ok")
	}

	p3Badge := int(p3[0])<<8 | int(p3[1])
	p4Badge := int(p4[0])<<8 | int(p4[1])

	if len(dumpOnce) == 2 && p3[2] == dumpOnce[0] && p3[3] == dumpOnce[1] {
		score += 3
		reasons = append(reasons, "p3 dump once matches")
	}
	if badgeIDHint != nil && p3Badge == *badgeIDHint {
		score += 2
		reasons = append(reasons, "p3 badge matches hint")
	}
	if p3Badge == p4Badge {
		score += 3
		reasons = append(reasons, "p3/p4 badge match")
	}
	if t4HeaderBadgeID != nil && p4Badge == *t4HeaderBadgeID {
		score += 2
		reasons = append(reasons, "p4 badge matches type4 header")
	}
	if string(p4[2:5]) == string(p3[6:9]) {
		score += 4
		reasons = append(reasons, "vendo nonce echoed")
	}
	if string(p4[5:7]) == string(p3[4:6]) {
		score += 3
		reasons = append(reasons, "credit amount echoed")
	}
	if p4[7] != p3[2] && p4[8] != p3[3] {
		score += 3
		reasons = append(reasons, "new once bytes differ")
	}

	strict := p3Checksum &&
		p4Checksum &&
		(len(dumpOnce) == 2 && p3[2] == dumpOnce[0] && p3[3] == dumpOnce[1]) &&
		(p3Badge == p4Badge) &&
		(badgeIDHint == nil || p3Badge == *badgeIDHint) &&
		(t4HeaderBadgeID == nil || p4Badge == *t4HeaderBadgeID) &&
		(string(p4[2:5]) == string(p3[6:9])) &&
		(string(p4[5:7]) == string(p3[4:6])) &&
		(p4[7] != p3[2]) &&
		(p4[8] != p3[3])

	return Candidate{
		StrictMatch:      strict,
		Score:            score,
		Reasons:          reasons,
		Type3PlainHex:    hex.EncodeToString(p3),
		Type4PlainHex:    hex.EncodeToString(p4),
		BadgeIDFromPlain: p3Badge,
		RequestedCredits: hex.EncodeToString(p3[4:6]),
		VendoOnceHex:     hex.EncodeToString(p3[6:9]),
	}
}

func scoreFromType3Plaintext(p3, dumpOnce []byte, badgeIDHint *int, requestedCredits []byte) Candidate {
	score := 0
	reasons := []string{}
	p3Checksum := checksumZero(p3)
	if p3Checksum {
		score += 2
		reasons = append(reasons, "p3 checksum ok")
	}
	p3Badge := int(p3[0])<<8 | int(p3[1])
	if len(dumpOnce) == 2 && p3[2] == dumpOnce[0] && p3[3] == dumpOnce[1] {
		score += 3
		reasons = append(reasons, "p3 dump once matches")
	}
	if badgeIDHint != nil && p3Badge == *badgeIDHint {
		score += 2
		reasons = append(reasons, "p3 badge matches hint")
	}
	if len(requestedCredits) == 2 && p3[4] == requestedCredits[0] && p3[5] == requestedCredits[1] {
		score += 3
		reasons = append(reasons, "p3 requested credits match")
	}
	return Candidate{
		StrictMatch:      false,
		Score:            score,
		Reasons:          reasons,
		Type3PlainHex:    hex.EncodeToString(p3),
		Type4PlainHex:    "",
		BadgeIDFromPlain: p3Badge,
		RequestedCredits: hex.EncodeToString(p3[4:6]),
		VendoOnceHex:     hex.EncodeToString(p3[6:9]),
	}
}

func parseUint32Arg(s string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
	return uint32(v), err
}

func fmtSecs(secs float64) string {
	if secs < 0 {
		secs = 0
	}
	n := int(secs)
	h := n / 3600
	rem := n % 3600
	m := rem / 60
	s := rem % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

func main() {
	type3Hex := flag.String("type3-hex", "", "")
	type4Hex := flag.String("type4-hex", "", "")
	type3Only := flag.Bool("type3-only", false, "use only the type 3 frame and report p3 survivors without decrypting type 4")
	dumpOnceHex := flag.String("dump-once-hex", "", "")
	badgeIDArg := flag.String("badge-id", "", "optional badge id hint")
	requestedCreditsArg := flag.String("requested-credits", "", "optional requested credits hint, e.g. 0x0001")
	seed32sArg := flag.String("seed32s", "", "optional comma-separated seed list")
	startSeed32Arg := flag.String("start-seed32", "0", "")
	endSeed32Arg := flag.String("end-seed32", "0xffffffff", "")
	descending := flag.Bool("descending", true, "scan seed range from end down to start")
	stopOnFirstStrict := flag.Bool("stop-on-first-strict", true, "stop issuing new seeds after first strict match")
	keysPerSeed := flag.Int("keys-per-seed", DEFAULT_KEYS_PER_SEED, "")
	workers := flag.Int("workers", runtime.NumCPU(), "")
	progressEverySec := flag.Float64("progress-every-sec", 5.0, "")
	printStage1 := flag.Bool("print-stage1", false, "print each stage-1 pass as it happens")
	topN := flag.Int("top", 20, "")
	reportPath := flag.String("report", "go_drand48_oracle_scan.json", "")
	flag.Parse()

	if *type3Hex == "" || *dumpOnceHex == "" || (!*type3Only && *type4Hex == "") {
		if *type3Only {
			fmt.Fprintln(os.Stderr, "--type3-hex and --dump-once-hex are required for --type3-only")
		} else {
			fmt.Fprintln(os.Stderr, "--type3-hex, --type4-hex, and --dump-once-hex are required")
		}
		os.Exit(2)
	}

	t3, err := parseSmashOrCipher(*type3Hex, 0x03)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var t4 ParsedInput
	if !*type3Only {
		t4, err = parseSmashOrCipher(*type4Hex, 0x04)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	dumpOnce, err := hex.DecodeString(cleanHex(*dumpOnceHex))
	if err != nil || len(dumpOnce) != 2 {
		fmt.Fprintln(os.Stderr, "--dump-once-hex must be exactly 2 bytes / 4 hex chars")
		os.Exit(2)
	}

	var badgeIDHint *int
	if strings.TrimSpace(*badgeIDArg) != "" {
		v, err := strconv.ParseUint(strings.TrimSpace(*badgeIDArg), 0, 32)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		x := int(v)
		badgeIDHint = &x
	}

	var requestedCredits []byte
	if strings.TrimSpace(*requestedCreditsArg) != "" {
		rc, err := hex.DecodeString(cleanHex(*requestedCreditsArg))
		if err != nil || len(rc) != 2 {
			fmt.Fprintln(os.Stderr, "--requested-credits must be exactly 2 bytes / 4 hex chars")
			os.Exit(2)
		}
		requestedCredits = rc
	}

	var seedList []uint32
	if strings.TrimSpace(*seed32sArg) != "" {
		for _, part := range strings.Split(*seed32sArg, ",") {
			v, err := parseUint32Arg(part)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			seedList = append(seedList, v)
		}
	}

	startSeed32, err := parseUint32Arg(*startSeed32Arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	endSeed32, err := parseUint32Arg(*endSeed32Arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(seedList) == 0 && endSeed32 < startSeed32 {
		fmt.Fprintln(os.Stderr, "end-seed32 must be >= start-seed32")
		os.Exit(2)
	}
	if *keysPerSeed <= 0 {
		fmt.Fprintln(os.Stderr, "--keys-per-seed must be >= 1")
		os.Exit(2)
	}
	if *workers <= 0 {
		*workers = runtime.NumCPU()
	}

	seedCh := make(chan uint32, *workers*2)
	matchCh := make(chan Candidate, 1024)

	var processedSeeds uint64
	var processedCandidates uint64
	var stage1Survivors uint64
	var strictMatchCountAtomic uint64
	var currentSeedAtomic uint64
	var stopRequested uint32

	var wg sync.WaitGroup
	workerFn := func() {
		defer wg.Done()
		for seed32 := range seedCh {
			eachDrand48Key(seed32, *keysPerSeed, func(keyIndex int, keyBytes []byte) {
				atomic.AddUint64(&processedCandidates, 1)

				p3, err := decryptExactBytes(keyBytes, t3.Ciphertext10)
				if err != nil {
					return
				}
				if p3[2] != dumpOnce[0] || p3[3] != dumpOnce[1] {
					return
				}
				p3Badge := int(p3[0])<<8 | int(p3[1])
				if badgeIDHint != nil && p3Badge != *badgeIDHint {
					return
				}
				if len(requestedCredits) == 2 && (p3[4] != requestedCredits[0] || p3[5] != requestedCredits[1]) {
					return
				}
				if !checksumZero(p3) {
					return
				}
				atomic.AddUint64(&stage1Survivors, 1)

				var cand Candidate
				if *type3Only {
					cand = scoreFromType3Plaintext(p3, dumpOnce, badgeIDHint, requestedCredits)
				} else {
					p4, err := decryptExactBytes(keyBytes, t4.Ciphertext10)
					if err != nil {
						return
					}
					cand = scoreFromPlaintexts(p3, p4, dumpOnce, badgeIDHint, t4.HeaderBadgeID)
					if cand.StrictMatch {
						atomic.AddUint64(&strictMatchCountAtomic, 1)
						if *stopOnFirstStrict {
							atomic.CompareAndSwapUint32(&stopRequested, 0, 1)
						}
					}
				}
				cand.Seed32 = seed32
				cand.KeyIndex = keyIndex
				cand.KeyHex = hex.EncodeToString(keyBytes)
				if *printStage1 {
					if *type3Only {
						fmt.Printf("stage1 candidate: seed32=%d key_index=%d key=%s score=%d p3=%s\n", cand.Seed32, cand.KeyIndex, cand.KeyHex, cand.Score, cand.Type3PlainHex)
					} else {
						fmt.Printf("stage1 pass: seed32=%d key_index=%d key=%s p3=%s\n", cand.Seed32, cand.KeyIndex, cand.KeyHex, cand.Type3PlainHex)
					}
				}
				matchCh <- cand
			})
			atomic.AddUint64(&processedSeeds, 1)
		}
	}

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go workerFn()
	}

	go func() {
		if len(seedList) > 0 {
			for _, s := range seedList {
				if atomic.LoadUint32(&stopRequested) != 0 {
					break
				}
				atomic.StoreUint64(&currentSeedAtomic, uint64(s))
				seedCh <- s
			}
		} else if *descending {
			for s := endSeed32; ; s-- {
				if atomic.LoadUint32(&stopRequested) != 0 {
					break
				}
				atomic.StoreUint64(&currentSeedAtomic, uint64(s))
				seedCh <- s
				if s == startSeed32 {
					break
				}
			}
		} else {
			for s := startSeed32; ; s++ {
				if atomic.LoadUint32(&stopRequested) != 0 {
					break
				}
				atomic.StoreUint64(&currentSeedAtomic, uint64(s))
				seedCh <- s
				if s == endSeed32 {
					break
				}
			}
		}
		close(seedCh)
		wg.Wait()
		close(matchCh)
	}()

	var strictMatches []Candidate
	var top []Candidate
	t0 := time.Now()
	totalSeeds := uint64(len(seedList))
	if totalSeeds == 0 {
		totalSeeds = uint64(endSeed32-startSeed32) + 1
	}

	doneCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Duration(*progressEverySec * float64(time.Second)))
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				ps := atomic.LoadUint64(&processedSeeds)
				currentSeed := atomic.LoadUint64(&currentSeedAtomic)
				s1 := atomic.LoadUint64(&stage1Survivors)
				strictNow := atomic.LoadUint64(&strictMatchCountAtomic)
				elapsed := time.Since(t0).Seconds()
				rate := float64(ps) / elapsed
				remaining := float64(totalSeeds - ps)
				eta := 0.0
				if rate > 0 {
					eta = remaining / rate
				}
				fmt.Printf("Seed=%d seed/s=%.1f stage1=%d strict=%d eta=%s\n",
					currentSeed, rate, s1, strictNow, fmtSecs(eta))
			}
		}
	}()

	for cand := range matchCh {
		if cand.StrictMatch {
			strictMatches = append(strictMatches, cand)
		}
		top = append(top, cand)
		sort.Slice(top, func(i, j int) bool {
			if top[i].Score != top[j].Score {
				return top[i].Score > top[j].Score
			}
			if top[i].Seed32 != top[j].Seed32 {
				return top[i].Seed32 < top[j].Seed32
			}
			return top[i].KeyIndex < top[j].KeyIndex
		})
		if len(top) > *topN {
			top = top[:*topN]
		}
	}
	close(doneCh)

	sort.Slice(strictMatches, func(i, j int) bool {
		if strictMatches[i].Seed32 != strictMatches[j].Seed32 {
			return strictMatches[i].Seed32 < strictMatches[j].Seed32
		}
		return strictMatches[i].KeyIndex < strictMatches[j].KeyIndex
	})

	rep := Report{}
	rep.Inputs.Model = "drand48"
	rep.Inputs.Type3Kind = t3.Kind
	rep.Inputs.Type4Kind = t4.Kind
	rep.Inputs.Type4HeaderBadgeID = t4.HeaderBadgeID
	rep.Inputs.Type3ChecksumOK = t3.ChecksumOK
	rep.Inputs.Type4ChecksumOK = t4.ChecksumOK
	rep.Inputs.Type3Only = *type3Only
	rep.Inputs.DumpOnceHex = hex.EncodeToString(dumpOnce)
	rep.Inputs.BadgeIDHint = badgeIDHint
	if len(requestedCredits) == 2 {
		rep.Inputs.RequestedCreditsHex = hex.EncodeToString(requestedCredits)
	}
	if len(seedList) > 0 {
		parts := make([]string, len(seedList))
		for i, s := range seedList {
			parts[i] = fmt.Sprintf("%d", s)
		}
		rep.Inputs.Seed32s = strings.Join(parts, ",")
	} else {
		rep.Inputs.StartSeed32 = fmt.Sprintf("0x%08x", startSeed32)
		rep.Inputs.EndSeed32 = fmt.Sprintf("0x%08x", endSeed32)
	}
	rep.Inputs.Descending = *descending
	rep.Inputs.StopOnFirstStrict = *stopOnFirstStrict
	rep.Inputs.KeysPerSeed = *keysPerSeed
	rep.Inputs.Workers = *workers
	rep.ProcessedSeeds = atomic.LoadUint64(&processedSeeds)
	rep.ProcessedCandidates = atomic.LoadUint64(&processedCandidates)
	rep.Stage1Survivors = atomic.LoadUint64(&stage1Survivors)
	rep.StrictMatchCount = len(strictMatches)
	rep.StrictMatches = strictMatches
	if len(top) > 0 {
		rep.Best = &top[0]
	}
	rep.Top = top

	js, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*reportPath, js, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", *reportPath)
	if *type3Only {
		fmt.Printf("type3-only survivors: %d\n", len(top))
		if len(top) > 0 {
			best := top[0]
			fmt.Printf("best type3-only candidate: key=%s seed32=%d key_index=%d score=%d\n", best.KeyHex, best.Seed32, best.KeyIndex, best.Score)
		}
	} else if len(strictMatches) > 0 {
		best := strictMatches[0]
		fmt.Printf("strict matches: %d\n", len(strictMatches))
		fmt.Printf("best strict key=%s seed32=%d key_index=%d\n", best.KeyHex, best.Seed32, best.KeyIndex)
	} else if len(top) > 0 {
		best := top[0]
		fmt.Printf("no strict match; best ranked candidate:\n")
		fmt.Printf("key=%s seed32=%d key_index=%d score=%d\n", best.KeyHex, best.Seed32, best.KeyIndex, best.Score)
	}
}

func comma(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	pre := len(s) % 3
	if pre == 0 {
		pre = 3
	}
	out = append(out, s[:pre]...)
	for i := pre; i < len(s); i += 3 {
		out = append(out, ',')
		out = append(out, s[i:i+3]...)
	}
	return string(out)
}
