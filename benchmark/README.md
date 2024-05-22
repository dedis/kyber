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

# Public benchmarks
If you don't want to run the benchmarks yourself, you can find them [here](https://dedis.github.io/kyber/benchmark)