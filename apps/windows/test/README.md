# Windows integration tests

Black-box tests for the Windows CLI live here. They run the real executable package in `../main` rather than importing package internals.

Package-level Go unit tests remain beside the implementation in `../main` because they deliberately exercise unexported policy and validation helpers.

Run the complete Windows suite from the repository root:

```sh
go -C apps/windows test ./...
```
