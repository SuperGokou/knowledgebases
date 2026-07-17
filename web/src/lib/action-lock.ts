export interface ActionLock {
  acquire: () => boolean;
  release: () => void;
  isLocked: () => boolean;
}

export function createActionLock(): ActionLock {
  let locked = false;
  return {
    acquire() {
      if (locked) return false;
      locked = true;
      return true;
    },
    release() {
      locked = false;
    },
    isLocked() {
      return locked;
    },
  };
}
