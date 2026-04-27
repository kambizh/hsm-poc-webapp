# hsm-poc-webapp

A lightweight Spring Boot web application used to demonstrate and validate HSM-based cryptographic operations using the `payshield-crypto-client` library.

## Purpose

This application serves as a Proof of Concept (POC) UI layer to verify integration with Thales payShield 10K HSM. It provides a simple interface to test digital signing and signature validation workflows.

The goal is to demonstrate end-to-end interaction with the HSM while keeping the application logic minimal.

## How to start
nohup java -jar hsm-poc-webapp-1.0.0-SNAPSHOT.jar &

## Features

- Input arbitrary message data
- Generate digital signature via HSM (EW command)
- Display raw signature output
- Verify signature using corresponding public key
- Show validation result (VALID / INVALID)
- Display HSM response codes for transparency

