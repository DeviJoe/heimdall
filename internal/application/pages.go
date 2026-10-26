package application

import "encoding/json"

type PageQuery struct {
	Limit                         int
	After, Search, Status, Parent string
}
type Page struct {
	Items []json.RawMessage
	Next  string
}
