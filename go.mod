module main

require github.com/spirilis/spitter/alerts v0.0.0

require (
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/spirilis/spitter/alerts v0.0.0 => ./alerts

go 1.20
