export type LatestRequestOutcome = "applied" | "superseded";

export type LatestRequestController = {
  invalidate: () => void;
  run: <T>(request: () => Promise<T>, apply: (value: T) => void) => Promise<LatestRequestOutcome>;
};

export function createLatestRequestController(): LatestRequestController {
  let latestRequest = 0;
  return {
    invalidate() {
      latestRequest += 1;
    },
    async run<T>(request: () => Promise<T>, apply: (value: T) => void) {
      latestRequest += 1;
      const requestSequence = latestRequest;
      try {
        const value = await request();
        if (requestSequence !== latestRequest) return "superseded";
        apply(value);
        return "applied";
      } catch (error) {
        if (requestSequence !== latestRequest) return "superseded";
        throw error;
      }
    },
  };
}
