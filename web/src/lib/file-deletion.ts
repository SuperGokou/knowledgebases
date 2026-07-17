type FileDeletePrincipal = { id: string; is_superuser: boolean } | null;
type OwnedFile = { owner_id: string };

export function canDeleteFile(principal: FileDeletePrincipal, file: OwnedFile): boolean {
  return Boolean(principal && (principal.is_superuser || file.owner_id === principal.id));
}
