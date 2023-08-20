module github.com/b-sn/mtls-sert

go 1.20

replace github.com/b-sn/x509wrapper v1.1.0 => ../x509wrapper

replace github.com/b-sn/passwd v0.1.0 => ../passwd

require (
	github.com/b-sn/passwd v0.1.0
	github.com/b-sn/x509wrapper v1.1.0
	github.com/google/uuid v1.3.0
	github.com/logrusorgru/aurora v2.0.3+incompatible
	gopkg.in/yaml.v2 v2.4.0
)
