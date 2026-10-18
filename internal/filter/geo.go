package filter

import "strings"

// SuspendedCountries are the ISO 3166-1 alpha-2 codes of the countries whose
// nationals are subject to full or partial entry suspension under the U.S.
// presidential proclamation of December 16, 2025 (effective January 1, 2026),
// as summarized in CRS Insight IN12631
// (https://www.congress.gov/crs-product/IN12631). PS covers the Palestinian
// Authority travel documents named in the proclamation.
var SuspendedCountries = []string{
	// Full suspension.
	"af", // Afghanistan
	"bf", // Burkina Faso
	"mm", // Burma
	"td", // Chad
	"cg", // Republic of the Congo
	"gq", // Equatorial Guinea
	"er", // Eritrea
	"ht", // Haiti
	"ir", // Iran
	"la", // Laos
	"ly", // Libya
	"ml", // Mali
	"ne", // Niger
	"sl", // Sierra Leone
	"so", // Somalia
	"ss", // South Sudan
	"sd", // Sudan
	"sy", // Syria
	"ye", // Yemen
	"ps", // Palestinian Authority

	// Partial suspension.
	"ao", // Angola
	"ag", // Antigua and Barbuda
	"bj", // Benin
	"bi", // Burundi
	"ci", // Cote d'Ivoire
	"cu", // Cuba
	"dm", // Dominica
	"ga", // Gabon
	"gm", // The Gambia
	"mw", // Malawi
	"mr", // Mauritania
	"ng", // Nigeria
	"sn", // Senegal
	"tz", // Tanzania
	"tg", // Togo
	"to", // Tonga
	"tm", // Turkmenistan
	"ve", // Venezuela
	"zm", // Zambia
	"zw", // Zimbabwe
}

// CountryBlocklistURLs returns the ipdeny.com aggregated zone URLs (one CIDR
// per line) for the given country codes. IPv6 zones are included only when
// withIPv6 is set: forwarded IPv6 is dropped outright otherwise, and some
// countries (e.g. Eritrea) publish no IPv6 zone at all.
func CountryBlocklistURLs(codes []string, withIPv6 bool) []string {
	var urls []string
	for _, c := range codes {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		urls = append(urls, "https://www.ipdeny.com/ipblocks/data/aggregated/"+c+"-aggregated.zone")
		if withIPv6 {
			urls = append(urls, "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/"+c+"-aggregated.zone")
		}
	}
	return urls
}
