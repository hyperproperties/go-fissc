# go-fissc

## Discrepancies
FISSC uses global variables as a parameter passing mechanism instead of just using parameters. I guess that the main motivation for this is the ease of use in the oracles. However, I have converted them to parameters.

"g_authenticated" is only made such that the result of verification can be used by the oracles. Therfore, this is ommitted and the return values are passed to the oracles.

## Potential Vulnerabilities
It is not possible to force inlining in Go. Therefore, a sinle bit flip in a non-inlined funtion will reach a braoder attack surface as all callers are affected.