import {
  Bls12381G2KeyPair,
  BbsBlsSignature2020 as MattrBbsBlsSignature2020,
} from "@mattrglobal/jsonld-signatures-bbs";
import { KeyType } from "@sphereon/ssi-sdk-bls-kms-local";
import { hexToMultibase, MultibaseFormat } from "@sphereon/ssi-sdk-core";
import { IVerifiableCredential } from "@sphereon/ssi-types";
import { IKey, IKeyManager, TKeyType } from "@veramo/core";
import { asArray } from "@veramo/utils";

import { SphereonLdSignature } from "../ld-suites";

export enum VerificationType {
  Bls12381G2Key2020 = "Bls12381G2Key2020",
}

export class SphereonBbsBlsSignature2020 extends SphereonLdSignature {
  constructor() {
    super();
  }

  getSupportedVerificationType(): string {
    return VerificationType.Bls12381G2Key2020;
  }

  getSupportedVeramoKeyType(): TKeyType {
    return KeyType.Bls12381G2;
  }

  getContext(): string {
    return "https://w3id.org/security/bbs/v1";
  }

  getSuiteForSigning(
    key: IKey,
    issuerDid: string,
    verificationMethodId: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    keyManager: Pick<IKeyManager, "keyManagerGet" | "keyManagerSign">
  ): any {
    const controller = issuerDid;

    const id = verificationMethodId;

    if (!key.privateKeyHex) {
      throw new Error("Private key must be defined");
    }

    const keyPairOptions = {
      id: id,
      controller: controller,
      privateKeyBase58: hexToMultibase(
        key.privateKeyHex,
        MultibaseFormat.BASE58
      ).value.substring(1),
      publicKeyBase58: hexToMultibase(
        key.publicKeyHex,
        MultibaseFormat.BASE58
      ).value.substring(1),
      type: this.getSupportedVerificationType(),
    };

    const bls12381G2KeyPair: Bls12381G2KeyPair = new Bls12381G2KeyPair(
      keyPairOptions
    );

    const signatureSuiteOptions = {
      key: bls12381G2KeyPair,
      verificationMethod: verificationMethodId,
    };
    return new MattrBbsBlsSignature2020(signatureSuiteOptions);
  }

  preVerificationCredModification(credential: IVerifiableCredential): void {
    const vcJson = JSON.stringify(credential);
    if (vcJson.indexOf("BbsBlsSignature2020") > -1) {
      if (vcJson.indexOf(this.getContext()) === -1) {
        credential["@context"] = [
          ...asArray(credential["@context"] || []),
          this.getContext(),
        ];
      }
    }
  }

  getSuiteForVerification(): any {
    return new MattrBbsBlsSignature2020();
  }

  // preSigningCredModification(_credential: CredentialPayload): void {}
  preSigningCredModification(): void {
    // nothing to do here
  }

  // preDidResolutionModification(_didUrl: string, _didDoc: DIDDocument): void {
  preDidResolutionModification(): void {
    // nothing to do here
  }
}
