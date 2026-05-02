# NIST Testing Guide

## Introduction
This document serves as a comprehensive guide on the NIST statistical tests used for assessing the quality of random number generators. The NIST test suite is widely utilized in cryptography and other applications where randomness is crucial.

## Fundamentals
- **NIST** (National Institute of Standards and Technology) provides a set of statistical tests for evaluating the randomness of binary sequences.
- The suite consists of 15 different tests designed to identify various statistical weaknesses in random number generators.

## Tests Overview
1. **Frequency (Monobit) Test**
   - Tests whether the number of ones and zeros in a binary sequence is approximately the same.
2. **Block Frequency Test**
   - Examines the proportion of ones in blocks of the sequence.
3. **Cumulative Sums Test**
   - Evaluates the cumulative sums of the ones and zeros across the sequence.
4. **Runs Test**
   - Assesses the occurrence and length of runs of identical bits in the sequence.
5. **Spectral Test**
   - Analyzes the periodicity of a sequence through the Discrete Fourier Transform.

(Expand on each test with detail on methodology, statistical criteria, and significance.)

## References
- [NIST Test Suite Documentation](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1/archive/2009-10-01)
- [NIST Statistical Test Suite: Practical Guidelines](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22.pdf)

## Code Explanation
The NIST test suite implementation can be broken down into several components:
- **Input Handling**: Code that accepts binary sequences from various sources (files, streams, etc.).
- **Test Execution**: Functions that carry out the statistical tests on the input data.
- **Result Reporting**: Mechanisms to output results in a readable format, including pass/fail outcomes and p-values.


