import { fetchProfile } from "./api/client";

export function App() {
  return fetchProfile("current-user");
}
