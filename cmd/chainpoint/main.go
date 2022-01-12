package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/boki/chainpoint"
)

func main() {
	var node string
	var cntType string
	flag.StringVar(&node, "node", "", "A node URI")
	flag.StringVar(&cntType, "content-type", chainpoint.ContentTypeJSON, "The content type of response: "+chainpoint.ContentTypeJSON+", "+chainpoint.ContentTypeBase64)
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Printf("ERR: No command specified")
		return
	} else if cntType != chainpoint.ContentTypeJSON && cntType != chainpoint.ContentTypeBase64 {
		log.Printf("ERR: Content type %s not supported", cntType)
		return
	}

	svc, err := chainpoint.New(http.DefaultClient)
	if err != nil {
		log.Printf("ERR: Could not create chainpoint service: %v", err)
		return
	}

	if node == "" {
		uris, err := svc.Nodes(1)
		if err != nil {
			log.Printf("ERR: Could not retrieve Node URI: %v", err)
			return
		}
		node = uris[0]
	}
	log.Printf("Using Node URI %s", node)

	ctx := context.Background()
	switch args[0] {
	case "hashes":
		hashes := strings.Split(args[1], ",")
		res, err := svc.Hashes(ctx, node, hashes)
		if err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		printRes(res)
	case "proofs":
		hashIDNodes := strings.Split(args[1], ",")
		res, err := svc.Proofs(ctx, node, hashIDNodes, cntType)
		if err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		printRes(res)
	case "verify":
		var proofs []*chainpoint.Chainpoint
		if err := json.Unmarshal([]byte(args[1]), &proofs); err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		res, err := svc.Verify(ctx, node, proofs)
		if err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		printRes(res)

	case "calendar":
		height := args[1]
		res, err := svc.Calendar(ctx, node, height)
		if err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		printRes(res)
	case "calendar-hash":
		height := args[1]
		res, err := svc.CalendarHash(ctx, node, height)
		if err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		log.Printf("%s", res)
	case "calendar-data":
		height := args[1]
		res, err := svc.CalendarData(ctx, node, height)
		if err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		log.Printf("%s", res)

	case "config":
		res, err := svc.Config(ctx, node)
		if err != nil {
			log.Printf("ERR: %v", err)
			return
		}
		printRes(res)

	default:
		log.Printf("ERR: Unknown command %s", args[0])
		return
	}
}

func printRes(res interface{}) error {
	d, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	log.Printf("%s", string(d))
	return nil
}
