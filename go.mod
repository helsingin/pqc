module github.com/helsingin/pqc

go 1.26.0

// Withdrawn milestone releases: direct Keyman adapter and audit-retry scope removed.
retract [v0.2.1, v0.2.2]

require (
	filippo.io/age v1.3.1
	github.com/cloudflare/circl v1.6.5
)

require (
	filippo.io/hpke v0.4.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
