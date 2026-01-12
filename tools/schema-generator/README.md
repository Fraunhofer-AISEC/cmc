# README

The schema generator generates JSON schema definitions for a golang cmc package for documentation.

## Build

```sh
go build
```

## Run

The `package` flag specifies the package the definition shall be generated for. the `out` flag
specifies the output folder. If the folder does not exist, it will be created. If the folder
exists, content will be overwritten.

```
./schema-generator [-package <package>] [-out <output-dir>]
```

## Update CMC documentation

See [update-api](../../bin/update-api)
