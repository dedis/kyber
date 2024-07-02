# Benchmark

This folder contains the script to measure the performance of various components in Kyber.

## Running the Benchmarks on your local machine

To run the benchmarks, follow these steps:

1. Clone the repository:

    ```shell
    git clone https://github.com/dedis/kyber.git
    ```

2. Navigate to the benchmark directory:

    ```shell
    cd benchmark
    ```

3. Run the benchmarks:

    ```shell
    go run benchmark.go
    ```

If you want a data visualization tool for the benchmarks, then simply fork the repository, execute the steps above and push your changes to master branch. Then, wait for the deploy workflow to finish and you'll have the platform on the endpoint ___your_username.github.io/kyber/benchmark___ (or a different domain if you set a custom one).

## Benchmarked Items

So far, the following items are benchmarked in this project:

- All the groups implemented in kyber (Ed25519, P256, Residue512, bn254, bn256)
- Anon and Bls signatures

For more up-to-date details on the benchmarked items, refer to the `benchmark.go` file.

## Adding benchmarks
### Adding a group
To add a new group to the benchmarks you just need to add to the `suites` list the suite you want to test.

Here's an example:
<pre>
var (
	...
	suites = []kyber.Group{
            ...
            edwards25519.NewBlakeSHA256Ed25519(),
            <b>suiteYouWannaAdd.suiteFactory()</b>
        }
	...
)
</pre>

### Adding a signature
For signatures there's no a unified interface as for groups, thus you would need to:
1. Add the new signature name `newSignature` to the `signatures` list
2. Add custom code in `benchmarkSign` when `sigType` == `newSignature`

Future work can be focused on creating a homogeneous benchmarking interface for all signatures and simplify their inclusion in the benchmark collection script.

### Adding a different module
So far only groups and signatures are supported. If you want to add a new module:
1. Fill the `main` method by adding a new key to `results` with the name of the new module to benchmark.
2. Create a custom function `benchmarkNewModule` which returns a dictionary following the Json structure:
```json
{ 
    "instance": { // instance of the given module
        "benchmarks": { // fixed key word
        "type": { // type of operations supported
            "operation": { // name of the specific atomic operation
            "N": // total number of iterations
            "T": // total time in nanoseconds
            "Bytes": // total number of bytes allocated
            ...
            }, ...
        }, ...
        }, 
    "description": // description displayed on front-end
    "name": // name displayed on front-end
    }, ...
}
```
Take a look at the actual Json [data](../docs/benchmark-app/src/data/data.json) as reference.
3. Update the [benchmark-app](../docs/benchmark-app/) to support the new module.

# Public benchmarks
If you don't want to run the benchmarks yourself, you can find them [here](https://dedis.github.io/kyber/benchmark)