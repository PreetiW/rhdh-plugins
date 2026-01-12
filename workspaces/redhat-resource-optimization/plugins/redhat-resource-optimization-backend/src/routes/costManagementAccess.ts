/*
 * Copyright Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { RequestHandler } from 'express';
import type { RouterOptions } from '../models/RouterOptions';
import {
  authorize,
  filterAuthorizedClusterIds,
} from '../util/checkPermissions';
import { costPluginPermissions } from '@red-hat-developer-hub/plugin-redhat-resource-optimization-common/permissions';
import { AuthorizeResult } from '@backstage/plugin-permission-common';
import { getTokenFromApi } from '../util/tokenUtil';

// Cache keys for cost management clusters
const COST_CLUSTERS_CACHE_KEY = 'cost_clusters';
const COST_PROJECTS_CACHE_KEY = 'cost_projects';
const CACHE_TTL = 15 * 60 * 1000; // 15 minutes

export const getCostManagementAccess: (
  options: RouterOptions,
) => RequestHandler = options => async (_, response) => {
  const { logger, permissions, httpAuth, cache, costManagementApi } = options;
  let finalDecision = AuthorizeResult.DENY;

  // Check for cost.plugin permission
  // If user has cost.plugin permission, allow access to all data
  const costPluginDecision = await authorize(
    _,
    costPluginPermissions,
    permissions,
    httpAuth,
  );

  logger.info(`Checking cost.plugin permission:`, costPluginDecision);

  if (costPluginDecision.result === AuthorizeResult.ALLOW) {
    finalDecision = AuthorizeResult.ALLOW;

    const body = {
      decision: finalDecision,
      authorizedClusterNames: [],
      authorizeProjects: [],
    };
    return response.json(body);
  }

  // RBAC Filtering logic for Cluster using cost.{clusterName} and cost.{clusterName}.{projectName} permissions
  let clusterDataMap: Record<string, string> = {};
  let allProjects: string[] = [];

  // Check the cluster & project data in the cache first
  const clustersFromCache = (await cache.get(COST_CLUSTERS_CACHE_KEY)) as
    | Record<string, string>
    | undefined;

  const projectsFromCache = (await cache.get(COST_PROJECTS_CACHE_KEY)) as
    | string[]
    | undefined;

  if (clustersFromCache && projectsFromCache) {
    clusterDataMap = clustersFromCache;
    allProjects = projectsFromCache;

    logger.info(
      `[CACHE HIT] Using cached data: ${
        Object.keys(clusterDataMap).length
      } clusters, ${allProjects.length} projects`,
    );
  } else {
    // Fetch clusters and projects from Cost Management API
    logger.info(
      `[CACHE MISS] Fetching clusters and projects from API with limit: 1000`,
    );
    try {
      const token = await getTokenFromApi(options);

      const [clustersResponse, projectsResponse] = await Promise.all([
        costManagementApi.searchOpenShiftClusters('', { token, limit: 1000 }),
        costManagementApi.searchOpenShiftProjects('', { token, limit: 1000 }),
      ]);

      const clustersData = await clustersResponse.json();
      const projectsData = await projectsResponse.json();

      logger.info(`Porject Data: ${JSON.stringify(projectsData)}`);

      // Extract cluster names from response
      clustersData.data?.map(
        (cluster: { value: string; cluster_alias: string }) => {
          if (cluster.cluster_alias && cluster.value)
            logger.info(
              `Cluster: ${cluster.cluster_alias} -> ${cluster.value}`,
            );
          clusterDataMap[cluster.cluster_alias] = cluster.value;
        },
      );

      // Extract project names from response
      allProjects =
        projectsData.data?.map((p: { value: string }) => p.value) ?? [];

      logger.info(
        `Fetched Projects from API: ${allProjects.toString()}, ${
          allProjects.length
        } projects`,
      );

      // Store in cache
      await cache.set(COST_CLUSTERS_CACHE_KEY, clusterDataMap, {
        ttl: CACHE_TTL,
      });
      await cache.set(COST_PROJECTS_CACHE_KEY, allProjects, { ttl: CACHE_TTL });
    } catch (error) {
      logger.error(`Failed to fetch clusters from Cost Management API`, error);
      throw error;
    }
  }

  // Filter clusters based on cost.{clusterName} permissions
  const authorizedClusterNames: string[] = await filterAuthorizedClusterIds(
    _,
    permissions,
    httpAuth,
    clusterDataMap,
    'cost',
  );

  // If user has access to at least one cluster, allow access
  if (authorizedClusterNames.length > 0) {
    finalDecision = AuthorizeResult.ALLOW;
  }

  const body = {
    decision: finalDecision,
    authorizedClusterNames,
    authorizeProjects: [],
  };

  return response.json(body);
};
