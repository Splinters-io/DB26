package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	dbcrypto "db26/internal/crypto"
	"db26/internal/intel"
	"db26/internal/paths"
	"db26/internal/wire"
)

type FileState struct {
	Chunks   map[uint32][]byte // seq → data
	Total    uint32
	FirstSeen time.Time
	LastSeen  time.Time
	Sources  map[string]bool // resolver IPs
}

func main() {
	fmt.Println()
	fmt.Println("  ██████╗ ██████╗ ██████╗  ██████╗  ██████╗ ███████╗ ██████╗██╗   ██╗")
	fmt.Println("  ██╔══██╗██╔══██╗╚════██╗██╔════╝  ██╔══██╗██╔════╝██╔════╝██║   ██║")
	fmt.Println("  ██║  ██║██████╔╝ █████╔╝███████╗  ██████╔╝█████╗  ██║     ██║   ██║")
	fmt.Println("  ██║  ██║██╔══██╗██╔═══╝ ██╔═══██╗ ██╔══██╗██╔══╝  ██║     ╚██╗ ██╔╝")
	fmt.Println("  ██████╔╝██████╔╝███████╗╚██████╔╝ ██║  ██║███████╗╚██████╗ ╚████╔╝")
	fmt.Println("  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═══╝")
	fmt.Println("  DataBouncing Receiver")
	fmt.Println()

	var (
		logPath      string
		passphrase   string
		salt         string
		fileIDHex    string
		corrIDsStr   string
		oobDomainsStr string
		outputDir    string
		enrichIPs    bool
	)

	flag.StringVar(&logPath, "log", paths.InteractshLogFile(), "Interactsh server log")
	flag.StringVar(&passphrase, "passphrase", "", "Decryption passphrase (required)")
	flag.StringVar(&salt, "salt", "", "Session salt hex (required)")
	flag.StringVar(&fileIDHex, "file-id", "", "File ID hex to extract (optional — extracts all if empty)")
	flag.StringVar(&corrIDsStr, "corr-ids", "", "Comma-separated correlation IDs (required)")
	flag.StringVar(&oobDomainsStr, "oob-domains", "", "Comma-separated OOB domains")
	flag.StringVar(&outputDir, "output", ".", "Output directory for reassembled files")
	flag.BoolVar(&enrichIPs, "enrich", false, "Enrich resolver IPs with ASN/Geo intel")
	flag.Parse()

	if passphrase == "" || salt == "" || corrIDsStr == "" {
		fmt.Fprintf(os.Stderr, "  Required: -passphrase, -salt, -corr-ids\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Derive session key from passphrase + salt
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid salt hex: %s\n", err)
		os.Exit(1)
	}
	sk := dbcrypto.DeriveKeyFromSalt(passphrase, saltBytes)
	fmt.Printf("[*] Session key derived\n")
	fmt.Printf("[*] Field lengths: fileID=%d, seq=%d, total=%d\n", sk.FieldLens[0], sk.FieldLens[1], sk.FieldLens[2])

	corrIDs := make(map[string]bool)
	for _, id := range strings.Split(corrIDsStr, ",") {
		corrIDs[strings.TrimSpace(id)] = true
	}
	oobDomains := strings.Split(oobDomainsStr, ",")

	fmt.Printf("[*] Correlation IDs: %d\n", len(corrIDs))
	fmt.Printf("[*] OOB domains: %v\n", oobDomains)

	var targetFileID uint32
	filterFileID := false
	if fileIDHex != "" {
		val, err := dbcrypto.UnpackUint32(fileIDHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Invalid file-id: %s\n", err)
			os.Exit(1)
		}
		targetFileID = val
		filterFileID = true
		fmt.Printf("[*] Extracting file ID: %03x\n", targetFileID)
	}

	// Parse interactsh log
	fmt.Printf("[*] Reading log: %s\n", logPath)

	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Open log: %s\n", err)
		os.Exit(1)
	}
	defer f.Close()

	files := make(map[uint32]*FileState)
	totalParsed := 0
	totalMatched := 0
	totalDecoded := 0

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		totalParsed++

		if totalParsed%500000 == 0 {
			fmt.Printf("[*] Parsed %d lines, %d matched, %d decoded...\n", totalParsed, totalMatched, totalDecoded)
		}

		// Quick filter: must contain a corr ID
		hasCorr := false
		for cid := range corrIDs {
			if strings.Contains(strings.ToLower(line), cid) {
				hasCorr = true
				break
			}
		}
		if !hasCorr {
			continue
		}
		totalMatched++

		// Extract full-id from JSON
		jsonStart := strings.Index(line, "{")
		if jsonStart == -1 {
			continue
		}

		var interaction struct {
			FullID        string `json:"full-id"`
			RemoteAddress string `json:"remote-address"`
			Protocol      string `json:"protocol"`
		}
		if err := json.Unmarshal([]byte(line[jsonStart:]), &interaction); err != nil {
			continue
		}

		if interaction.Protocol != "dns" {
			continue
		}

		// Parse full-id directly: labels are everything before the corrID
		fqdn := strings.ToLower(interaction.FullID)

		// Find and strip the correlation ID
		var dataLabels []string
		allLabels := strings.Split(fqdn, ".")
		foundCorr := false
		for _, label := range allLabels {
			if corrIDs[label] {
				foundCorr = true
			} else {
				dataLabels = append(dataLabels, label)
			}
		}
		if !foundCorr || len(dataLabels) < 3 {
			continue
		}

		// Decode the remaining labels (shuffled fields + possible decoys)
		chunk, err := wire.DecodeSubdomain(dataLabels, sk)
		if err != nil {
			continue
		}
		decoded := true
		_ = decoded

		if filterFileID && chunk.FileID != targetFileID {
			continue
		}

		totalDecoded++

		// Store chunk
		state, exists := files[chunk.FileID]
		if !exists {
			state = &FileState{
				Chunks:    make(map[uint32][]byte),
				Total:     chunk.Total,
				FirstSeen: time.Now(),
				Sources:   make(map[string]bool),
			}
			files[chunk.FileID] = state
			fmt.Printf("[+] New file detected: %03x (%d total chunks)\n", chunk.FileID, chunk.Total)
		}

		if _, dup := state.Chunks[chunk.Seq]; !dup {
			state.Chunks[chunk.Seq] = chunk.Data
			state.LastSeen = time.Now()
		}
		state.Sources[interaction.RemoteAddress] = true

		// Check if complete
		if uint32(len(state.Chunks)) == state.Total {
			fmt.Printf("[+] File %03x complete! (%d/%d chunks)\n", chunk.FileID, len(state.Chunks), state.Total)
		}
	}

	fmt.Printf("\n[*] Log parsing complete: %d lines, %d matched, %d decoded\n", totalParsed, totalMatched, totalDecoded)

	// Reassemble each file
	os.MkdirAll(outputDir, 0755)

	for fileID, state := range files {
		fmt.Printf("\n  ════════════════════════════════════════\n")
		fmt.Printf("  File %03x\n", fileID)
		fmt.Printf("  ════════════════════════════════════════\n")
		fmt.Printf("  Chunks:    %d / %d\n", len(state.Chunks), state.Total)

		// Check for missing chunks
		missing := []uint32{}
		for i := uint32(0); i < state.Total; i++ {
			if _, ok := state.Chunks[i]; !ok {
				missing = append(missing, i)
			}
		}
		if len(missing) > 0 {
			fmt.Printf("  Missing:   %d chunks", len(missing))
			if len(missing) <= 20 {
				fmt.Printf(" (seq: %v)", missing)
			}
			fmt.Println()
			fmt.Printf("  Status:    INCOMPLETE\n")
			continue
		}

		// Reassemble
		var assembled []byte
		for i := uint32(0); i < state.Total; i++ {
			assembled = append(assembled, state.Chunks[i]...)
		}

		// First 32 bytes are SHA-256 checksum, rest is encrypted data
		if len(assembled) < 32 {
			fmt.Printf("  Status:    ERROR (payload too short)\n")
			continue
		}
		expectedChecksum := assembled[:32]
		encrypted := assembled[32:]

		// Decrypt
		plaintext, err := dbcrypto.Decrypt(sk.Key, encrypted)
		if err != nil {
			fmt.Printf("  Status:    DECRYPT FAILED (%s)\n", err)
			continue
		}

		// Verify checksum
		actualChecksum := dbcrypto.Checksum(plaintext)
		checksumOK := true
		for i := range expectedChecksum {
			if i < len(actualChecksum) && expectedChecksum[i] != actualChecksum[i] {
				checksumOK = false
				break
			}
		}

		if !checksumOK {
			fmt.Printf("  Status:    CHECKSUM MISMATCH\n")
			fmt.Printf("  Expected:  %s\n", hex.EncodeToString(expectedChecksum[:8]))
			fmt.Printf("  Actual:    %s\n", hex.EncodeToString(actualChecksum[:8]))
			continue
		}

		// Write output
		outPath := fmt.Sprintf("%s/file_%03x.dat", outputDir, fileID)
		if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
			fmt.Printf("  Status:    WRITE ERROR (%s)\n", err)
			continue
		}

		fmt.Printf("  Size:      %d bytes\n", len(plaintext))
		fmt.Printf("  Checksum:  %s (VERIFIED)\n", hex.EncodeToString(actualChecksum[:8]))
		fmt.Printf("  Output:    %s\n", outPath)
		fmt.Printf("  Resolvers: %d unique IPs\n", len(state.Sources))

		// Enrich resolver IPs
		if enrichIPs && len(state.Sources) > 0 {
			fmt.Printf("\n  Resolver Intelligence:\n")
			ips := make([]string, 0, len(state.Sources))
			for ip := range state.Sources {
				ips = append(ips, ip)
			}
			infos := intel.LookupIPs(ips)
			for _, info := range infos {
				fmt.Printf("    %s\n", intel.Summarize(info))
			}
		}

		fmt.Printf("  Status:    SUCCESS\n")
	}

	if len(files) == 0 {
		fmt.Printf("\n[*] No data chunks found for the given correlation IDs.\n")
		fmt.Printf("[*] Ensure the sender has completed and callbacks have arrived.\n")
	}
}
