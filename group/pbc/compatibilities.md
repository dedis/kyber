# Compatibilities issues with dfinity/crypto/.../mcl.go

## Scalar / Field element

+ SetInt:
    - In dfinity, `SetInt(i int)`
    - In dedis, `SetInt64(i int64)`


# Open questions

+ Is it safe to pass the same reference to Fr.Neg() as out and in ?
+ What is the bitlength of the scalar Fr ?
+ What are the verifications for Deserialize ? Why does it return an error ?
  Because of the SetBytes() which does not return any error.



