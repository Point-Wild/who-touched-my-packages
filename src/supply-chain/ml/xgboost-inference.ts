/**
 * Lightweight XGBoost inference engine for TypeScript.
 * Loads an XGBoost JSON model and runs tree-based prediction.
 *
 * No native dependencies — pure TypeScript.
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

interface TreeNode {
  nodeid: number;
  split?: string;          // feature index as "f0", "f1", etc.
  split_condition?: number;
  yes?: number;
  no?: number;
  missing?: number;
  leaf?: number;
  children?: TreeNode[];
  depth?: number;
}

interface XGBoostTree {
  tree_id: number;
  nodes: TreeNode[];
}

interface XGBoostModel {
  learner: {
    gradient_booster: {
      model: {
        trees: Array<{
          tree_param: { num_nodes: string };
          split_indices: number[];
          split_conditions: number[];
          left_children: number[];
          right_children: number[];
          default_left: number[];
        }>;
      };
    };
    learner_model_param: {
      base_score: string | number | number[];
      num_feature: string;
    };
  };
}

let cachedModel: {
  trees: Array<{
    splitIndices: number[];
    splitConditions: number[];
    leftChildren: number[];
    rightChildren: number[];
    defaultLeft: number[];
    numNodes: number;
  }>;
  baseScore: number;
  numFeatures: number;
} | null = null;

function loadModel(): typeof cachedModel {
  if (cachedModel) return cachedModel;

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const modelPath = join(__dirname, 'model.json');
  const raw = JSON.parse(readFileSync(modelPath, 'utf-8')) as XGBoostModel;

  const gboost = raw.learner.gradient_booster.model;
  const params = raw.learner.learner_model_param;

  const trees = gboost.trees.map(t => ({
    splitIndices: t.split_indices,
    splitConditions: t.split_conditions,
    leftChildren: t.left_children,
    rightChildren: t.right_children,
    defaultLeft: t.default_left,
    numNodes: parseInt(t.tree_param.num_nodes),
  }));

  // base_score can be a string like "[5E-1]", a number, or an array
  const rawStr = String(params.base_score).replace(/[\[\]]/g, '');
  const baseScore = parseFloat(rawStr);

  cachedModel = {
    trees,
    baseScore,
    numFeatures: parseInt(params.num_feature),
  };

  return cachedModel;
}

function predictTree(
  tree: typeof cachedModel extends null ? never : NonNullable<typeof cachedModel>['trees'][0],
  features: number[],
): number {
  let nodeId = 0;

  while (true) {
    const leftChild = tree.leftChildren[nodeId];

    // Leaf node: left_children[nodeId] === -1
    if (leftChild === -1) {
      return tree.splitConditions[nodeId]; // leaf value stored in split_conditions
    }

    const featureIdx = tree.splitIndices[nodeId];
    const threshold = tree.splitConditions[nodeId];
    const rightChild = tree.rightChildren[nodeId];

    const value = features[featureIdx];

    if (value === undefined || Number.isNaN(value)) {
      // Missing value — use default direction
      nodeId = tree.defaultLeft[nodeId] === 1 ? leftChild : rightChild;
    } else if (value < threshold) {
      nodeId = leftChild;
    } else {
      nodeId = rightChild;
    }
  }
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

/**
 * Predict malicious probability for a feature vector.
 * Returns a number between 0 and 1.
 */
export function predictMaliciousProba(features: number[]): number {
  const model = loadModel()!;

  // XGBoost binary:logistic stores base_score as probability (0.5).
  // Convert to logit: logit(0.5) = 0.
  const baseLogit = Math.log(model.baseScore / (1 - model.baseScore));

  let sum = baseLogit;
  for (const tree of model.trees) {
    sum += predictTree(tree, features);
  }

  return sigmoid(sum);
}

/**
 * Predict malicious probability for multiple feature vectors.
 */
export function predictBatch(featureBatch: number[][]): number[] {
  return featureBatch.map(predictMaliciousProba);
}

/**
 * Get model info.
 */
export function getModelInfo(): { numTrees: number; numFeatures: number } {
  const model = loadModel()!;
  return { numTrees: model.trees.length, numFeatures: model.numFeatures };
}
