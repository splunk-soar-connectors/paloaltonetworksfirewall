**Unreleased**

* Block bare URL hosts and their subdomains while warning when a pathful URL remains exact.
* Use service any for connector-created IP and application containment deny rules.
* Migrate the connector URL policy to a top-priority category-scoped deny rule that remains inert when empty.
* Reject CIDR /0 and IP wildcard masks while continuing to support valid IP addresses, ranges, and CIDRs.
