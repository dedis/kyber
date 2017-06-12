# Compatibilities issues with dfinity/crypto/.../mcl.go

## Scalar / Field element

+ SetInt:
    - In dfinity, `SetInt(i int)`
    - In dedis, `SetInt64(i int64)`

+ Is there any reasons
## Group element

+ Missing methods:
    - `Null`
    - `Base`


# Open questions

+ Is it safe to pass the same reference to Fr.Neg() as out and in ?
+ What is the bitlength of the scalar Fr ?
+ What are the verifications for Fr.Deserialize ? Why does it return an error ?  Error is because out of bounds ? Because of the SetBytes() which does not return any error.
+ What is the bitlength of the group g1, g2 and gt ? Is it fixed "per config" ?  Currently marshalling first to know the size
+ Are they prime order curves ? 
+ What is g1.HashAndMapTo ?

## Second round

+ C.blsInit(curve) is global variable. this can be problematic.
+ GetCurveOrder(): 
    - comments saying returns order of G1, what about G2 ?
    - do you know if they are prime order or not ? Otherwise I'll run a long primality test, but I prefer to ask first ;)
+ Any difference between FrAdd and Secretkey.Add() ? From what I gather it's the same thing but want to make sure with you. Since we're using `Fr` as a "key" ..
+ I'm using `HashAndMapTo` for G1 and G2. Is it possible to get it for GT too ?
