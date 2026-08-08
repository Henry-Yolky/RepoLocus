import { selectShared } from "shared";

export function selectSharedBackend(): string {
  return selectShared();
}
