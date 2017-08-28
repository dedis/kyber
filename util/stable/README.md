# Creating a stable version of kyber

With the current development-model, `master` should stay in a more or
less stable state, but it has extensions that are not deemed stable.
This directory allows to extract the *stable* parts of kyber to be included
in a `v1` or other package-handling procedure.

Two files are in this directory:
- directories - a list of directories that are deemed stable
- create_stable.sh - a script to create a stable version

## create_stable.sh

This script takes as an argument the repository where you want to store
the stable version. It will:

- create that repo
- copy all directories and files from `directories`
- adjust all `github.com/dedis/kyber`-imports to that new repo
- copy files from `util/test/#{repo}` into the new repo
