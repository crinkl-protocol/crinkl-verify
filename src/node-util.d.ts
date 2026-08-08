declare module "node:util" {
  export const types: {
    isProxy(value: object): boolean;
  };
}
