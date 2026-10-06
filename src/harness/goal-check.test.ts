import { describe, expect, it } from "vitest";
import { PARENT_MODULE, premiseModule, STATEMENT_MODULE, statementModules } from "./goal-check";

const imports = (source: string) => source.split("\n").filter((line) => line.startsWith("import "));

describe("the modules a goal check compiles before the proof", () => {
  it("are the statement alone for a proof that assumes nothing", () => {
    const modules = statementModules({ imports: ["Mathlib"], contexts: ["def two : Nat := 2"], statement: "two = 2", proves: "goal" });
    expect(modules.map((module) => module.module)).toEqual([STATEMENT_MODULE]);
    expect(modules[0].source).toContain("def two : Nat := 2");
  });

  it("put each statement on its own chain, and compile a context the chains share once", () => {
    const modules = statementModules({
      imports: ["Mathlib"],
      contexts: ["def two : Nat := 2", "def four : Nat := 4"],
      statement: "two + two = four",
      proves: "goal",
      premises: [
        // A smaller goal of the goal, on its chain, and a lemma from another branch.
        { goal: "goal:under", contexts: ["def two : Nat := 2", "def four : Nat := 4", "def eight : Nat := 8"], statement: "four + four = eight" },
        { goal: "goal:elsewhere", contexts: ["def two : Nat := 2", "def six : Nat := 6"], statement: "two + four = six" },
      ],
    });
    const byName = new Map(modules.map((module) => [module.module, module]));
    // The root's context, the goal's, the smaller goal's, and the other branch's: four, each once.
    const contexts = modules.filter((module) => module.holds === "context");
    expect(contexts.map((module) => module.source.split("\n").find((line) => line.startsWith("def")))).toEqual([
      "def two : Nat := 2",
      "def four : Nat := 4",
      "def eight : Nat := 8",
      "def six : Nat := 6",
    ]);
    // The first imports the swarm's imports; each after it, the context above it.
    expect(imports(contexts[0].source)).toEqual(["import Mathlib"]);
    expect(imports(contexts[1].source)).toEqual([`import ${contexts[0].module}`]);
    expect(imports(contexts[2].source)).toEqual([`import ${contexts[1].module}`]);
    expect(imports(contexts[3].source)).toEqual([`import ${contexts[0].module}`]);
    expect(imports(byName.get(PARENT_MODULE)!.source)).toEqual([`import ${contexts[1].module}`]);
    expect(imports(byName.get(premiseModule(0))!.source)).toEqual([`import ${contexts[2].module}`]);
    expect(imports(byName.get(premiseModule(1))!.source)).toEqual([`import ${contexts[3].module}`]);
    // The statement joins them, last, naming constants only.
    expect(modules.at(-1)!.module).toBe(STATEMENT_MODULE);
    expect(imports(modules.at(-1)!.source)).toEqual([`import ${PARENT_MODULE}`, `import ${premiseModule(0)}`, `import ${premiseModule(1)}`]);
    expect(modules.at(-1)!.source).toContain("SJGoal.premise1 → SJGoal.premise2 → SJGoal.parent");
  });

  it("start a goal with no contexts from the swarm's imports", () => {
    const modules = statementModules({ imports: [], contexts: [], statement: "True", proves: "negation", premises: [{ goal: "goal:a", contexts: [], statement: "False" }] });
    expect(modules.map((module) => module.holds)).toEqual(["parent", "premise", "statement"]);
    expect(modules.at(-1)!.source).toContain("SJGoal.premise1 → ¬ SJGoal.parent");
  });
});
