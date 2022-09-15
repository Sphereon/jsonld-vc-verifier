import { purposes } from "@digitalcredentials/jsonld-signatures";

export type ContextDoc = {
  "@context": string | Record<string, any>;
};

export const ProofPurpose = purposes.ProofPurpose;
export const ControllerProofPurpose = purposes.ControllerProofPurpose;
export const AssertionProofPurpose = purposes.AssertionProofPurpose;
export const AuthenticationProofPurpose = purposes.AuthenticationProofPurpose;

export function isIterable<T>(obj: any): obj is Iterable<T> {
  return obj != null && typeof obj[Symbol.iterator] === "function";
}

export type OrPromise<T> = T | Promise<T>;

export type RecordLike<T> = Map<string, T> | Record<string, T>;
