declare const resolvers: {
  alwaysTryTypes: true;
  extensions: string[];
  mainFiles: ["index.gen", "index"];
  project: ["tsconfig.json", "**/*/tsconfig.json"];
};

export default resolvers;
