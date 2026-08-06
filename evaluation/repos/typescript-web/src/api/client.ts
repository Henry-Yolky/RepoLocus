export async function fetchProfile(userId: string): Promise<string> {
  return `/api/profiles/${userId}`;
}
