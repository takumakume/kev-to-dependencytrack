package kev

type Catalog struct {
	Title          string `json:"title"`
	CatalogVersion string `json:"catalogVersion"`
	DateReleased   string `json:"dateReleased"`
	Count          int    `json:"count"`

	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

func (c *Catalog) VulnerabilitiyIDs() []string {
	var ids []string
	for _, v := range c.Vulnerabilities {
		ids = append(ids, v.CveID)
	}
	return ids
}
