package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ascension-association/gk-fltr/internal/ndpi"
)

// protocols searches the protocols nDPI can detect, to find names for
// -protocols.
func protocols(args []string) error {
	fs := flag.NewFlagSet("gk-fltr protocols", flag.ExitOnError)
	license := fs.String("ndpi-license", "not-for-profit", "nDPI license mode: not-for-profit, for-profit-lgpl or for-profit-dual")
	category := fs.String("category", "", "only list protocols in this category, e.g. SocialNetwork")
	categories := fs.Bool("categories", false, "list the categories (with protocol counts) instead of protocols")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `usage: gk-fltr protocols [flags] [QUERY...]

Lists the protocols nDPI can detect whose name or category contains any QUERY
(case-insensitive), or all of them. Use the names, or category:NAME, with
-protocols, e.g. -protocols=YouTube,Instagram,category:SocialNetwork

flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	lic, err := ndpi.ParseLicense(*license)
	if err != nil {
		return err
	}
	mod, err := ndpi.New(lic)
	if err != nil {
		return err
	}
	defer mod.Close()
	ps := mod.Protocols()
	sort.Slice(ps, func(i, j int) bool { return strings.ToLower(ps[i].Name) < strings.ToLower(ps[j].Name) })

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	if *categories {
		count := map[string]int{}
		for _, p := range ps {
			count[p.Category]++
		}
		names := make([]string, 0, len(count))
		for c := range count {
			names = append(names, c)
		}
		sort.Strings(names)
		fmt.Fprintln(tw, "CATEGORY\tPROTOCOLS")
		for _, c := range names {
			fmt.Fprintf(tw, "%s\t%d\n", c, count[c])
		}
		return nil
	}

	var queries []string
	for _, q := range fs.Args() {
		queries = append(queries, strings.ToLower(q))
	}
	n := 0
	for _, p := range ps {
		if *category != "" && !strings.EqualFold(p.Category, *category) {
			continue
		}
		if len(queries) > 0 && !matchesAny(p, queries) {
			continue
		}
		if n == 0 {
			fmt.Fprintln(tw, "NAME\tCATEGORY\tBREED")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", p.Name, p.Category, p.Breed)
		n++
	}
	if n == 0 {
		return fmt.Errorf("no protocols match (try: gk-fltr protocols -categories)")
	}
	return nil
}

func matchesAny(p ndpi.ProtoInfo, queries []string) bool {
	name, cat := strings.ToLower(p.Name), strings.ToLower(p.Category)
	for _, q := range queries {
		if strings.Contains(name, q) || strings.Contains(cat, q) {
			return true
		}
	}
	return false
}

// resolveProtocols turns the -protocols list into nDPI protocol IDs. An
// entry is a protocol name or "category:NAME" for all protocols in a
// category (names are case-insensitive).
func resolveProtocols(mod *ndpi.Module, list string) ([]uint16, error) {
	var (
		ids  []uint16
		seen = map[uint16]bool{}
		all  []ndpi.ProtoInfo
	)
	add := func(id uint16) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if cat, ok := strings.CutPrefix(entry, "category:"); ok {
			if all == nil {
				all = mod.Protocols()
			}
			n := 0
			for _, p := range all {
				if strings.EqualFold(p.Category, cat) {
					add(p.ID)
					n++
				}
			}
			if n == 0 {
				return nil, fmt.Errorf("no nDPI protocols in category %q (see: gk-fltr protocols -categories)", cat)
			}
			continue
		}
		id, ok := mod.ProtoID(entry)
		if !ok {
			return nil, fmt.Errorf("unknown nDPI protocol %q (see: gk-fltr protocols %s)", entry, entry)
		}
		add(id)
	}
	return ids, nil
}
