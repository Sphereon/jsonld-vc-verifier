import { ICredential } from "@sphereon/ssi-types";
import {
  EcdsaSecp256k1RecoveryMethod2020,
  EcdsaSecp256k1RecoverySignature2020,
} from "@transmute/lds-ecdsa-secp256k1-recovery2020";
import { DIDDocument, IKey, IKeyManager, TKeyType } from "@veramo/core";
import { asArray, encodeJoseBlob } from "@veramo/utils";
import * as u8a from "uint8arrays";

import { SphereonLdSignature } from "../ld-suites";

export class SphereonEcdsaSecp256k1RecoverySignature2020 extends SphereonLdSignature {
  getSupportedVerificationType(): string {
    return "EcdsaSecp256k1RecoveryMethod2020";
  }

  getSupportedVeramoKeyType(): TKeyType {
    return "Secp256k1";
  }

  getSuiteForSigning(
    key: IKey,
    did: string,
    verifiableMethodId: string,
    keyManager: Pick<IKeyManager, "keyManagerGet" | "keyManagerSign">
  ): any {
    const controller = did;
    const signer = {
      //returns a JWS detached
      sign: async (args: { data: Uint8Array }): Promise<string> => {
        const header = {
          alg: "ES256K-R",
          b64: false,
          crit: ["b64"],
        };
        const headerString = encodeJoseBlob(header);
        const messageBuffer = u8a.concat([
          u8a.fromString(`${headerString}.`, "utf-8"),
          args.data,
        ]);
        const messageString = u8a.toString(messageBuffer, "base64");
        const signature = await keyManager.keyManagerSign({
          keyRef: key.kid,
          algorithm: "ES256K-R",
          data: messageString,
          encoding: "base64",
        });
        return `${headerString}..${signature}`;
      },
    };

    return new EcdsaSecp256k1RecoverySignature2020({
      // signer,
      key: new EcdsaSecp256k1RecoveryMethod2020({
        publicKeyHex: key.publicKeyHex,
        signer: () => signer,
        type: this.getSupportedVerificationType(),
        controller,
        id: verifiableMethodId,
      }),
    });
  }

  getSuiteForVerification(): any {
    return new EcdsaSecp256k1RecoverySignature2020();
  }

  preVerificationCredModification(): void {
    // nothing to do here
  }

  preSigningCredModification(credential: ICredential): void {
    credential["@context"] = [
      ...asArray(credential["@context"] || []),
      "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld",
    ];
  }

  preDidResolutionModification(didUrl: string, didDoc: DIDDocument): void {
    // did:ethr
    if (didUrl.toLowerCase().startsWith("did:ethr")) {
      // TODO: EcdsaSecp256k1RecoveryMethod2020 does not support blockchainAccountId
      // blockchainAccountId to ethereumAddress
      didDoc.verificationMethod?.forEach((x) => {
        if (x.blockchainAccountId) {
          x.ethereumAddress = x.blockchainAccountId.substring(
            0,
            x.blockchainAccountId.lastIndexOf("@")
          );
        }
      });
    }
  }

  getContext(): string {
    return "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld";
  }
}
