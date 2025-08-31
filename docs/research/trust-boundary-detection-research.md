# Advanced Trust Boundary Detection Algorithms and Implementations for Threat Modeling

## Executive Summary

This research document provides a comprehensive analysis of advanced trust boundary detection algorithms and implementations for threat modeling and infrastructure security analysis. The study examines academic research, open source implementations, cloud-native patterns, and machine learning approaches to identify security perimeters and trust boundaries in distributed systems.

**Key Findings:**
- Graph-based approaches show promise for automated boundary detection
- Cloud-native trust boundaries require dynamic detection algorithms
- Machine learning enables contextual trust assessment and anomaly detection
- Modern threat modeling tools use pattern-based detection methods
- Zero Trust architectures necessitate continuous boundary verification

## Table of Contents

1. [Introduction](#introduction)
2. [Academic Research on Trust Boundary Detection](#academic-research)
3. [Open Source Threat Modeling Tools Analysis](#open-source-tools)
4. [Network Segmentation Detection Algorithms](#network-segmentation)
5. [Cloud-Native Trust Boundary Patterns](#cloud-patterns)
6. [Graph-Based Approaches to Boundary Detection](#graph-approaches)
7. [Machine Learning Approaches](#ml-approaches)
8. [Implementation Recommendations for Threagile](#recommendations)
9. [Code Examples and Algorithms](#code-examples)
10. [Future Research Directions](#future-directions)

## 1. Introduction {#introduction}

Trust boundaries represent critical security perimeters where data or execution transitions between different trust levels, security domains, or control contexts. In distributed systems and cloud environments, identifying and modeling these boundaries is essential for effective threat modeling and security analysis.

Traditional perimeter-based security models are insufficient for modern distributed architectures. The challenge lies in automatically detecting and continuously monitoring trust boundaries across:

- Multi-cloud environments
- Microservices architectures
- Container orchestration platforms
- Edge computing deployments
- IoT ecosystems

This research examines advanced algorithmic approaches to automate trust boundary detection, with specific focus on implementations suitable for integration into threat modeling tools like Threagile.

## 2. Academic Research on Trust Boundary Detection {#academic-research}

### 2.1 Graph Theory Approaches

#### Network Boundary Recognition via Graph Theory
Research by wireless sensor network communities has developed algorithms for identifying nodes at network boundaries using graph-theoretical tools. The key algorithmic approach involves:

1. **Laplacian Spectrum Analysis**: Using the spectrum of the Laplacian matrix for robust network clustering
2. **Betweenness-Centrality Scoring**: Estimating cluster-border nodes based on betweenness-centrality scores
3. **Distributed Implementation**: Enabling autonomous boundary detection based on local connectivity information

**Algorithm Overview:**
```
1. Construct graph G(V,E) from system connectivity
2. Compute Laplacian matrix L = D - A
3. Analyze eigenvalues/eigenvectors of L for clustering
4. Calculate betweenness-centrality for boundary scoring
5. Identify nodes with high boundary scores as trust boundaries
```

#### Trust Evaluation in Distributed Networks
Academic research on graph-based trust models provides frameworks for evaluating trustworthiness in distributed systems:

- **TrustGNN**: Graph Neural Network-based trust evaluation systems
- **SocioTrust**: Probability-based trust models for distributed architectures
- **Graph-theoretic optimization**: Minimizing implementation costs while maintaining security boundaries

### 2.2 Zero Trust Research Landscape

Recent research emphasizes the shift from perimeter-based to continuous verification models:

- **Dynamic Trust Assessment**: Algorithms that continuously evaluate trust levels based on behavioral patterns
- **Distributed Zero Trust**: Frameworks for implementing zero trust in IoT and edge computing scenarios
- **Trust Boundary Blurring**: Research on handling unclear boundaries in cloud and edge environments

### 2.3 Network Security Boundary Research

Academic literature identifies several algorithmic approaches for boundary detection:

1. **Connectivity-based Detection**: Algorithms using only graph connectivity information
2. **Behavior-based Identification**: Methods analyzing communication patterns
3. **Hybrid Approaches**: Combining structural and behavioral analysis

## 3. Open Source Threat Modeling Tools Analysis {#open-source-tools}

### 3.1 OWASP Threat Dragon

**Trust Boundary Implementation:**
- Visual representation using red dotted lines
- Manual specification through diagram interface
- Integration with STRIDE threat modeling methodology
- Support for different boundary types (CorpNet, Sandbox, Internet, Browser)

**Technical Architecture:**
- Version 1.x: JointJS graph editing engine
- Version 2.x: AntV/X6 graph editing engine
- JSON-based model storage format
- Element-based threat generation

**Limitations:**
- Primarily manual boundary definition
- Limited automated detection capabilities
- UI-focused rather than algorithmic approach

### 3.2 Microsoft Threat Modeling Tool

**Trust Boundary Patterns:**
- Predefined boundary types (Corporate Network, Sandbox, Internet Explorer, Browser)
- Integration with STRIDE methodology
- Visual boundary representation with red dotted lines
- Automated threat generation based on boundary crossings

**Detection Approach:**
- Pattern-based identification
- Element property analysis
- Manual specification with automated threat analysis
- Focus on data flow diagram (DFD) analysis

**Key Insights:**
- Emphasizes manual specification over automated detection
- Strong integration between boundaries and threat generation
- Limited algorithmic sophistication

### 3.3 Analysis Summary

Current open source tools show limitations in automated trust boundary detection:

1. **Manual Definition**: Most tools require manual boundary specification
2. **Limited Algorithms**: Minimal algorithmic sophistication in boundary detection
3. **Visual Focus**: Emphasis on visual representation rather than automated analysis
4. **Pattern-Based**: Simple pattern matching rather than intelligent detection

**Opportunity for Threagile**: Significant potential for implementing advanced algorithmic approaches to automated trust boundary detection.

## 4. Network Segmentation Detection Algorithms {#network-segmentation}

### 4.1 Cloud Network Segmentation

#### VPC and Security Group Analysis
Modern cloud environments use software-defined networking for segmentation:

**Detection Algorithms:**
1. **Flow Log Analysis**: Analyzing VPC flow logs to detect traffic patterns and boundary violations
2. **Security Group Mapping**: Algorithmic analysis of security group rules to identify trust boundaries
3. **Network Topology Analysis**: Graph-based analysis of network connections and routing

**Implementation Approaches:**
```python
# Pseudocode for VPC boundary detection
def detect_vpc_boundaries(vpc_config):
    boundaries = []
    
    # Analyze security groups
    for sg in vpc_config.security_groups:
        if is_boundary_sg(sg):
            boundaries.append(create_boundary(sg))
    
    # Analyze subnets
    for subnet in vpc_config.subnets:
        if crosses_availability_zones(subnet):
            boundaries.append(create_az_boundary(subnet))
    
    # Analyze network ACLs
    for nacl in vpc_config.network_acls:
        if enforces_strict_isolation(nacl):
            boundaries.append(create_nacl_boundary(nacl))
    
    return boundaries
```

#### Network Security Groups and Microsegmentation
Algorithmic approaches to analyzing network security policies:

1. **Rule Conflict Detection**: Identifying conflicting or overlapping security rules
2. **Principle of Least Privilege Analysis**: Detecting overly permissive rules
3. **Segmentation Validation**: Verifying that intended segmentation is properly implemented

### 4.2 Traffic Flow Analysis

#### Anomaly Detection Algorithms
Network segmentation detection often relies on traffic flow analysis:

**Key Techniques:**
1. **Statistical Analysis**: Baseline normal traffic patterns and detect deviations
2. **Machine Learning Classification**: Training models to identify boundary-crossing traffic
3. **Graph-Based Flow Analysis**: Representing traffic flows as graphs and analyzing connectivity patterns

**Algorithm Framework:**
```
1. Collect network flow data (NetFlow, sFlow, VPC Flow Logs)
2. Build graph representation of traffic flows
3. Apply clustering algorithms to identify natural boundaries
4. Validate boundaries against security policies
5. Generate alerts for boundary violations
```

### 4.3 Continuous Monitoring Approaches

#### Real-Time Boundary Validation
Algorithms for continuous validation of trust boundaries:

1. **Policy Compliance Checking**: Automated verification of boundary enforcement
2. **Drift Detection**: Identifying configuration changes that affect boundaries
3. **Behavioral Analysis**: Monitoring for unusual cross-boundary communications

## 5. Cloud-Native Trust Boundary Patterns {#cloud-patterns}

### 5.1 AWS Trust Boundary Patterns

#### Account-Level Boundaries
AWS accounts provide the highest level of isolation:
- Complete resource isolation between accounts
- IAM-based access control within accounts
- Cross-account access through explicit trust relationships

#### VPC and Subnet Boundaries
Network-level trust boundaries in AWS:
```
Trust Boundary Hierarchy:
├── AWS Account (Strongest isolation)
├── AWS Region
├── VPC (Virtual Private Cloud)
├── Availability Zone
├── Subnet (Public/Private)
├── Security Group
└── Network ACL
```

#### IAM Trust Boundaries
Identity-based trust boundaries:
- Role assumption across accounts
- Policy-based access control
- Service-linked roles and boundaries

**Graph-Based IAM Analysis:**
```python
# Bipartite graph model for IAM analysis
def model_iam_as_graph(iam_config):
    G = nx.Graph()
    
    # Add principals (users, roles, groups)
    for principal in iam_config.principals:
        G.add_node(principal.id, type='principal')
    
    # Add actions/resources
    for action in iam_config.allowed_actions:
        G.add_node(action.id, type='action')
    
    # Add edges for permissions
    for policy in iam_config.policies:
        for statement in policy.statements:
            G.add_edge(statement.principal, statement.action,
                      weight=calculate_trust_score(statement))
    
    return G

def detect_trust_boundaries_in_iam(G):
    # Apply graph-cut algorithms to minimize privilege while 
    # maintaining business functionality
    boundaries = []
    
    # Find natural clusters in the permission graph
    communities = nx.community.greedy_modularity_communities(G)
    
    for community in communities:
        boundary = analyze_community_boundary(community, G)
        if boundary.is_significant():
            boundaries.append(boundary)
    
    return boundaries
```

### 5.2 Azure Trust Boundary Patterns

#### Subscription and Resource Group Boundaries
Azure's hierarchical boundary model:
```
Azure Trust Boundaries:
├── Management Group
├── Subscription (Primary billing and access boundary)
├── Resource Group (Logical grouping)
├── Virtual Network
├── Subnet
├── Network Security Group
└── Application Security Group
```

#### Network Security Perimeters
Azure's approach to defining security boundaries:
- Virtual Network isolation
- Private endpoints for PaaS services
- Network Security Perimeters for comprehensive boundary management

### 5.3 Google Cloud Trust Boundary Patterns

#### Project and Organization Boundaries
GCP's organizational trust model:
- Organization-level policies
- Project isolation
- VPC network boundaries
- IAM and service account boundaries

#### Detection Algorithm for Cloud Trust Boundaries
```python
def detect_cloud_trust_boundaries(cloud_config):
    """
    Universal cloud trust boundary detection algorithm
    """
    boundaries = []
    
    # Account/Subscription/Project level boundaries
    for account in cloud_config.accounts:
        boundaries.extend(detect_account_boundaries(account))
    
    # Network-level boundaries
    for network in cloud_config.networks:
        boundaries.extend(detect_network_boundaries(network))
    
    # IAM-based boundaries
    for iam_config in cloud_config.iam_configurations:
        boundaries.extend(detect_iam_boundaries(iam_config))
    
    # Service-specific boundaries
    for service in cloud_config.services:
        boundaries.extend(detect_service_boundaries(service))
    
    return consolidate_boundaries(boundaries)

def detect_account_boundaries(account):
    """Account-level boundary detection"""
    boundaries = []
    
    # Cross-account access patterns
    for trust_relationship in account.cross_account_trusts:
        boundary = TrustBoundary(
            type='account',
            source=account.id,
            target=trust_relationship.trusted_account,
            trust_level=evaluate_trust_level(trust_relationship)
        )
        boundaries.append(boundary)
    
    return boundaries

def detect_network_boundaries(network):
    """Network-level boundary detection"""
    boundaries = []
    
    # Subnet boundaries
    for subnet in network.subnets:
        if subnet.is_public():
            boundary = TrustBoundary(
                type='network',
                source=subnet.id,
                target='internet',
                trust_level=0.1  # Low trust for internet-facing
            )
            boundaries.append(boundary)
    
    # Security group boundaries
    for sg in network.security_groups:
        for rule in sg.rules:
            if rule.allows_cross_boundary_traffic():
                boundary = create_sg_boundary(rule)
                boundaries.append(boundary)
    
    return boundaries
```

## 6. Graph-Based Approaches to Boundary Detection {#graph-approaches}

### 6.1 Graph Theoretical Foundations

#### System Modeling as Graphs
Distributed systems can be modeled as graphs where:
- **Vertices (V)**: System components (services, databases, users, devices)
- **Edges (E)**: Communication links, trust relationships, data flows
- **Weights**: Trust levels, communication frequency, data sensitivity

#### Graph Properties for Boundary Detection
Key graph properties that indicate trust boundaries:

1. **Betweenness Centrality**: Nodes with high betweenness centrality often represent boundary components
2. **Graph Cuts**: Minimum cuts in the graph indicate natural boundaries
3. **Community Detection**: Graph communities often represent trust domains
4. **Spectral Analysis**: Eigenvalues of the Laplacian matrix reveal structural boundaries

### 6.2 Boundary Detection Algorithms

#### Spectral Clustering for Boundary Detection
```python
import numpy as np
from scipy.sparse.linalg import eigsh
from sklearn.cluster import KMeans

def spectral_boundary_detection(adjacency_matrix, num_boundaries=None):
    """
    Use spectral clustering to detect trust boundaries in a system graph
    """
    # Compute degree matrix
    degree_matrix = np.diag(np.sum(adjacency_matrix, axis=1))
    
    # Compute Laplacian matrix
    laplacian = degree_matrix - adjacency_matrix
    
    # Compute eigenvalues and eigenvectors
    if num_boundaries is None:
        # Use eigengap heuristic to determine number of clusters
        eigenvals, eigenvecs = eigsh(laplacian, k=10, which='SM')
        num_boundaries = find_eigengap(eigenvals)
    else:
        eigenvals, eigenvecs = eigsh(laplacian, k=num_boundaries, which='SM')
    
    # Use k-means clustering on eigenvectors
    kmeans = KMeans(n_clusters=num_boundaries)
    cluster_assignments = kmeans.fit_predict(eigenvecs[:, 1:num_boundaries])
    
    # Identify boundary edges (edges between different clusters)
    boundaries = []
    for i in range(len(adjacency_matrix)):
        for j in range(i+1, len(adjacency_matrix)):
            if adjacency_matrix[i][j] > 0 and cluster_assignments[i] != cluster_assignments[j]:
                boundaries.append({
                    'source': i,
                    'target': j,
                    'type': 'trust_boundary',
                    'strength': adjacency_matrix[i][j]
                })
    
    return boundaries, cluster_assignments

def find_eigengap(eigenvals):
    """Find the number of clusters using the eigengap heuristic"""
    gaps = np.diff(eigenvals)
    return np.argmax(gaps) + 2  # +2 because we want clusters, not gaps
```

#### Community Detection for Trust Domains
```python
import networkx as nx
from networkx.algorithms import community

def community_based_boundary_detection(graph):
    """
    Detect trust boundaries using community detection algorithms
    """
    boundaries = []
    
    # Apply multiple community detection algorithms
    algorithms = [
        ('modularity', community.greedy_modularity_communities),
        ('louvain', community.louvain_communities),
        ('label_propagation', community.label_propagation_communities)
    ]
    
    boundary_consensus = {}
    
    for algo_name, algo_func in algorithms:
        communities = algo_func(graph)
        
        # Find edges that cross community boundaries
        for edge in graph.edges():
            source, target = edge
            source_community = find_node_community(source, communities)
            target_community = find_node_community(target, communities)
            
            if source_community != target_community:
                edge_key = tuple(sorted([source, target]))
                if edge_key not in boundary_consensus:
                    boundary_consensus[edge_key] = 0
                boundary_consensus[edge_key] += 1
    
    # Select boundaries that are detected by multiple algorithms
    consensus_threshold = len(algorithms) // 2 + 1
    for edge, count in boundary_consensus.items():
        if count >= consensus_threshold:
            boundaries.append({
                'source': edge[0],
                'target': edge[1],
                'type': 'trust_boundary',
                'confidence': count / len(algorithms)
            })
    
    return boundaries

def find_node_community(node, communities):
    """Find which community a node belongs to"""
    for i, community_set in enumerate(communities):
        if node in community_set:
            return i
    return -1
```

#### Graph Cut Algorithms for Boundary Optimization
```python
def minimum_cut_boundary_detection(graph, source_nodes, sink_nodes):
    """
    Use minimum cut algorithms to find optimal trust boundaries
    """
    import networkx as nx
    
    # Create a copy of the graph for modification
    cut_graph = graph.copy()
    
    # Add super-source and super-sink nodes
    super_source = 'SUPER_SOURCE'
    super_sink = 'SUPER_SINK'
    
    cut_graph.add_node(super_source)
    cut_graph.add_node(super_sink)
    
    # Connect source nodes to super-source with infinite capacity
    for node in source_nodes:
        cut_graph.add_edge(super_source, node, capacity=float('inf'))
    
    # Connect sink nodes to super-sink with infinite capacity
    for node in sink_nodes:
        cut_graph.add_edge(node, super_sink, capacity=float('inf'))
    
    # Find minimum cut
    cut_value, partition = nx.minimum_cut(cut_graph, super_source, super_sink)
    
    source_partition, sink_partition = partition
    
    # Remove super nodes from partitions
    source_partition.discard(super_source)
    sink_partition.discard(super_sink)
    
    # Find boundary edges
    boundaries = []
    for node in source_partition:
        for neighbor in graph.neighbors(node):
            if neighbor in sink_partition:
                boundaries.append({
                    'source': node,
                    'target': neighbor,
                    'type': 'trust_boundary',
                    'cut_capacity': graph[node][neighbor].get('weight', 1)
                })
    
    return boundaries, cut_value
```

### 6.3 Advanced Graph Analysis Techniques

#### Centrality-Based Boundary Detection
```python
def centrality_based_boundary_detection(graph, threshold_percentile=90):
    """
    Identify trust boundaries based on node centrality measures
    """
    import networkx as nx
    import numpy as np
    
    # Calculate various centrality measures
    betweenness = nx.betweenness_centrality(graph)
    closeness = nx.closeness_centrality(graph)
    eigenvector = nx.eigenvector_centrality(graph, max_iter=1000)
    
    # Normalize centrality scores
    betweenness_values = list(betweenness.values())
    closeness_values = list(closeness.values())
    eigenvector_values = list(eigenvector.values())
    
    # Calculate thresholds
    bet_threshold = np.percentile(betweenness_values, threshold_percentile)
    close_threshold = np.percentile(closeness_values, threshold_percentile)
    eigen_threshold = np.percentile(eigenvector_values, threshold_percentile)
    
    # Identify boundary nodes (high centrality nodes)
    boundary_nodes = set()
    for node in graph.nodes():
        if (betweenness[node] > bet_threshold or 
            closeness[node] > close_threshold or 
            eigenvector[node] > eigen_threshold):
            boundary_nodes.add(node)
    
    # Find edges connected to boundary nodes
    boundaries = []
    for node in boundary_nodes:
        for neighbor in graph.neighbors(node):
            if neighbor not in boundary_nodes:
                boundaries.append({
                    'source': node,
                    'target': neighbor,
                    'type': 'trust_boundary',
                    'boundary_node_centrality': {
                        'betweenness': betweenness[node],
                        'closeness': closeness[node],
                        'eigenvector': eigenvector[node]
                    }
                })
    
    return boundaries, boundary_nodes
```

#### Multi-Layer Graph Analysis
```python
class MultiLayerTrustBoundaryDetector:
    """
    Detect trust boundaries in multi-layer graphs representing different
    aspects of a distributed system (network, application, data, identity)
    """
    
    def __init__(self):
        self.layers = {}
        self.inter_layer_edges = []
    
    def add_layer(self, layer_name, graph):
        """Add a layer to the multi-layer graph"""
        self.layers[layer_name] = graph
    
    def add_inter_layer_edge(self, layer1, node1, layer2, node2, weight=1):
        """Add edge between layers"""
        self.inter_layer_edges.append({
            'layer1': layer1,
            'node1': node1,
            'layer2': layer2,
            'node2': node2,
            'weight': weight
        })
    
    def detect_cross_layer_boundaries(self):
        """Detect boundaries that span multiple layers"""
        boundaries = []
        
        for edge in self.inter_layer_edges:
            # Analyze trust transition between layers
            layer1_graph = self.layers[edge['layer1']]
            layer2_graph = self.layers[edge['layer2']]
            
            # Get node properties from each layer
            node1_props = layer1_graph.nodes[edge['node1']]
            node2_props = layer2_graph.nodes[edge['node2']]
            
            # Calculate trust differential
            trust_diff = self.calculate_trust_differential(node1_props, node2_props)
            
            if trust_diff > 0.5:  # Significant trust boundary
                boundaries.append({
                    'type': 'cross_layer_boundary',
                    'layer1': edge['layer1'],
                    'node1': edge['node1'],
                    'layer2': edge['layer2'],
                    'node2': edge['node2'],
                    'trust_differential': trust_diff
                })
        
        return boundaries
    
    def calculate_trust_differential(self, node1_props, node2_props):
        """Calculate trust differential between nodes in different layers"""
        # Implement trust calculation based on node properties
        # This is a simplified example
        trust1 = node1_props.get('trust_level', 0.5)
        trust2 = node2_props.get('trust_level', 0.5)
        return abs(trust1 - trust2)
    
    def detect_intra_layer_boundaries(self):
        """Detect boundaries within each layer"""
        all_boundaries = []
        
        for layer_name, graph in self.layers.items():
            # Apply single-layer boundary detection algorithms
            boundaries = spectral_boundary_detection(nx.to_numpy_array(graph))
            
            for boundary in boundaries[0]:  # boundaries[0] contains the boundary list
                boundary['layer'] = layer_name
                all_boundaries.append(boundary)
        
        return all_boundaries
```

### 6.4 Graph-Based Trust Propagation

#### Trust Propagation Algorithms
```python
def trust_propagation_boundary_detection(graph, trusted_nodes, max_iterations=100, 
                                       convergence_threshold=0.001):
    """
    Detect trust boundaries using trust propagation algorithms
    """
    import numpy as np
    
    num_nodes = len(graph.nodes())
    node_to_index = {node: i for i, node in enumerate(graph.nodes())}
    index_to_node = {i: node for node, i in node_to_index.items()}
    
    # Initialize trust values
    trust_values = np.zeros(num_nodes)
    for node in trusted_nodes:
        trust_values[node_to_index[node]] = 1.0
    
    # Create adjacency matrix
    adjacency = nx.to_numpy_array(graph)
    
    # Normalize adjacency matrix (for trust propagation)
    row_sums = adjacency.sum(axis=1)
    row_sums[row_sums == 0] = 1  # Avoid division by zero
    normalized_adjacency = adjacency / row_sums[:, np.newaxis]
    
    # Trust propagation iterations
    for iteration in range(max_iterations):
        old_trust = trust_values.copy()
        
        # Propagate trust through the network
        trust_values = 0.85 * np.dot(normalized_adjacency.T, trust_values) + 0.15 * trust_values
        
        # Check convergence
        if np.linalg.norm(trust_values - old_trust) < convergence_threshold:
            break
    
    # Identify trust boundaries based on trust gradients
    boundaries = []
    trust_threshold = np.median(trust_values)
    
    for i, node1 in enumerate(graph.nodes()):
        for j, node2 in enumerate(graph.neighbors(node1)):
            node2_index = node_to_index[node2]
            
            # Check for significant trust differential
            trust_diff = abs(trust_values[i] - trust_values[node2_index])
            
            if trust_diff > trust_threshold and graph.has_edge(node1, node2):
                boundaries.append({
                    'source': node1,
                    'target': node2,
                    'type': 'trust_gradient_boundary',
                    'trust_differential': trust_diff,
                    'source_trust': trust_values[i],
                    'target_trust': trust_values[node2_index]
                })
    
    return boundaries, trust_values
```

## 7. Machine Learning Approaches {#ml-approaches}

### 7.1 Supervised Learning for Boundary Detection

#### Feature Engineering for Trust Boundaries
```python
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

class TrustBoundaryMLDetector:
    """
    Machine Learning-based trust boundary detector using supervised learning
    """
    
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_columns = []
    
    def extract_features(self, graph, edge):
        """Extract features for an edge to determine if it's a trust boundary"""
        source, target = edge
        
        features = {}
        
        # Node-level features
        features['source_degree'] = graph.degree(source)
        features['target_degree'] = graph.degree(target)
        features['degree_difference'] = abs(graph.degree(source) - graph.degree(target))
        
        # Centrality features
        betweenness = nx.betweenness_centrality(graph)
        closeness = nx.closeness_centrality(graph)
        
        features['source_betweenness'] = betweenness[source]
        features['target_betweenness'] = betweenness[target]
        features['betweenness_difference'] = abs(betweenness[source] - betweenness[target])
        
        features['source_closeness'] = closeness[source]
        features['target_closeness'] = closeness[target]
        features['closeness_difference'] = abs(closeness[source] - closeness[target])
        
        # Structural features
        features['common_neighbors'] = len(list(nx.common_neighbors(graph, source, target)))
        features['jaccard_coefficient'] = list(nx.jaccard_coefficient(graph, [edge]))[0][2]
        features['adamic_adar'] = list(nx.adamic_adar_index(graph, [edge]))[0][2]
        features['resource_allocation'] = list(nx.resource_allocation_index(graph, [edge]))[0][2]
        
        # Edge properties (if available)
        edge_data = graph.get_edge_data(source, target, {})
        features['edge_weight'] = edge_data.get('weight', 1.0)
        features['communication_frequency'] = edge_data.get('frequency', 0)
        features['data_sensitivity'] = edge_data.get('sensitivity', 0)
        
        # Node type features (if available)
        source_type = graph.nodes[source].get('type', 'unknown')
        target_type = graph.nodes[target].get('type', 'unknown')
        
        features['same_type'] = 1 if source_type == target_type else 0
        features['cross_layer'] = 1 if source_type != target_type else 0
        
        # Trust level features (if available)
        source_trust = graph.nodes[source].get('trust_level', 0.5)
        target_trust = graph.nodes[target].get('trust_level', 0.5)
        
        features['trust_differential'] = abs(source_trust - target_trust)
        features['min_trust'] = min(source_trust, target_trust)
        features['max_trust'] = max(source_trust, target_trust)
        
        return features
    
    def prepare_training_data(self, training_graphs, boundary_labels):
        """Prepare training data from labeled graphs"""
        features_list = []
        labels = []
        
        for graph, graph_boundaries in zip(training_graphs, boundary_labels):
            for edge in graph.edges():
                edge_features = self.extract_features(graph, edge)
                features_list.append(edge_features)
                
                # Check if this edge is labeled as a boundary
                is_boundary = edge in graph_boundaries or (edge[1], edge[0]) in graph_boundaries
                labels.append(1 if is_boundary else 0)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        self.feature_columns = features_df.columns.tolist()
        
        return features_df, np.array(labels)
    
    def train(self, training_graphs, boundary_labels):
        """Train the ML model"""
        X, y = self.prepare_training_data(training_graphs, boundary_labels)
        
        # Handle missing values
        X = X.fillna(0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        print("Model Performance:")
        print(classification_report(y_test, y_pred))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))
        
        return self.model
    
    def predict_boundaries(self, graph, threshold=0.5):
        """Predict trust boundaries in a new graph"""
        boundaries = []
        
        for edge in graph.edges():
            edge_features = self.extract_features(graph, edge)
            features_df = pd.DataFrame([edge_features])
            features_df = features_df.reindex(columns=self.feature_columns, fill_value=0)
            
            # Predict probability of being a boundary
            boundary_prob = self.model.predict_proba(features_df)[0][1]
            
            if boundary_prob > threshold:
                boundaries.append({
                    'source': edge[0],
                    'target': edge[1],
                    'type': 'ml_detected_boundary',
                    'confidence': boundary_prob,
                    'features': edge_features
                })
        
        return boundaries
```

### 7.2 Unsupervised Learning Approaches

#### Anomaly Detection for Boundary Identification
```python
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

class UnsupervisedBoundaryDetector:
    """
    Unsupervised learning approach to detect trust boundaries using anomaly detection
    """
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.dbscan = DBSCAN(eps=0.3, min_samples=5)
    
    def extract_node_features(self, graph):
        """Extract features for each node in the graph"""
        features = {}
        
        # Calculate centrality measures
        betweenness = nx.betweenness_centrality(graph)
        closeness = nx.closeness_centrality(graph)
        eigenvector = nx.eigenvector_centrality(graph, max_iter=1000)
        pagerank = nx.pagerank(graph)
        
        # Calculate clustering coefficients
        clustering = nx.clustering(graph)
        
        for node in graph.nodes():
            node_features = {
                'degree': graph.degree(node),
                'betweenness_centrality': betweenness[node],
                'closeness_centrality': closeness[node],
                'eigenvector_centrality': eigenvector[node],
                'pagerank': pagerank[node],
                'clustering_coefficient': clustering[node]
            }
            
            # Add node-specific attributes if available
            node_data = graph.nodes[node]
            node_features.update({
                'trust_level': node_data.get('trust_level', 0.5),
                'security_level': node_data.get('security_level', 0),
                'exposure_score': node_data.get('exposure_score', 0)
            })
            
            features[node] = node_features
        
        return features
    
    def detect_anomalous_nodes(self, graph):
        """Detect nodes that are anomalous and likely to be on boundaries"""
        node_features = self.extract_node_features(graph)
        
        # Convert to matrix
        feature_matrix = []
        node_list = []
        
        for node, features in node_features.items():
            feature_matrix.append(list(features.values()))
            node_list.append(node)
        
        feature_matrix = np.array(feature_matrix)
        
        # Scale features
        scaled_features = self.scaler.fit_transform(feature_matrix)
        
        # Detect anomalies
        anomaly_scores = self.isolation_forest.fit_predict(scaled_features)
        anomaly_probs = self.isolation_forest.decision_function(scaled_features)
        
        # Identify anomalous nodes
        anomalous_nodes = []
        for i, (node, is_anomaly) in enumerate(zip(node_list, anomaly_scores)):
            if is_anomaly == -1:  # -1 indicates anomaly in Isolation Forest
                anomalous_nodes.append({
                    'node': node,
                    'anomaly_score': anomaly_probs[i],
                    'features': node_features[node]
                })
        
        return anomalous_nodes
    
    def detect_boundaries_from_anomalies(self, graph, anomalous_nodes):
        """Find trust boundaries based on anomalous nodes"""
        boundaries = []
        anomalous_node_set = {item['node'] for item in anomalous_nodes}
        
        for node_info in anomalous_nodes:
            node = node_info['node']
            
            # Check edges from this anomalous node
            for neighbor in graph.neighbors(node):
                if neighbor not in anomalous_node_set:
                    # Edge between anomalous and normal node - likely boundary
                    boundaries.append({
                        'source': node,
                        'target': neighbor,
                        'type': 'anomaly_based_boundary',
                        'anomaly_score': node_info['anomaly_score'],
                        'boundary_reason': 'anomalous_to_normal_transition'
                    })
        
        return boundaries
    
    def cluster_based_boundary_detection(self, graph):
        """Use clustering to identify natural groupings and boundaries"""
        node_features = self.extract_node_features(graph)
        
        # Convert to matrix
        feature_matrix = []
        node_list = []
        
        for node, features in node_features.items():
            feature_matrix.append(list(features.values()))
            node_list.append(node)
        
        feature_matrix = np.array(feature_matrix)
        scaled_features = self.scaler.fit_transform(feature_matrix)
        
        # Apply DBSCAN clustering
        cluster_labels = self.dbscan.fit_predict(scaled_features)
        
        # Create node-to-cluster mapping
        node_clusters = {}
        for node, cluster in zip(node_list, cluster_labels):
            node_clusters[node] = cluster
        
        # Find edges that cross cluster boundaries
        boundaries = []
        for edge in graph.edges():
            source, target = edge
            if node_clusters[source] != node_clusters[target]:
                boundaries.append({
                    'source': source,
                    'target': target,
                    'type': 'cluster_boundary',
                    'source_cluster': node_clusters[source],
                    'target_cluster': node_clusters[target]
                })
        
        return boundaries, node_clusters
```

### 7.3 Deep Learning Approaches

#### Graph Neural Networks for Trust Boundary Detection
```python
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool
from torch_geometric.data import Data, DataLoader

class TrustBoundaryGNN(nn.Module):
    """
    Graph Neural Network for trust boundary detection
    """
    
    def __init__(self, input_dim, hidden_dim=64, output_dim=2, num_layers=3):
        super(TrustBoundaryGNN, self).__init__()
        
        self.num_layers = num_layers
        self.convs = nn.ModuleList()
        
        # Input layer
        self.convs.append(GCNConv(input_dim, hidden_dim))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))
        
        # Output layer
        self.convs.append(GCNConv(hidden_dim, hidden_dim))
        
        # Edge classifier
        self.edge_classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(hidden_dim, output_dim)
        )
        
        self.dropout = nn.Dropout(0.5)
        
    def forward(self, x, edge_index, batch=None):
        # Node embeddings through GCN layers
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = self.dropout(x)
        
        # For each edge, concatenate source and target node embeddings
        edge_embeddings = []
        for i in range(edge_index.size(1)):
            source_idx, target_idx = edge_index[:, i]
            edge_embedding = torch.cat([x[source_idx], x[target_idx]], dim=0)
            edge_embeddings.append(edge_embedding)
        
        edge_embeddings = torch.stack(edge_embeddings)
        
        # Classify each edge as boundary or not
        edge_predictions = self.edge_classifier(edge_embeddings)
        
        return edge_predictions

class TrustBoundaryDataset:
    """
    Dataset class for trust boundary detection
    """
    
    def __init__(self, graphs, labels):
        self.graphs = graphs
        self.labels = labels
    
    def __len__(self):
        return len(self.graphs)
    
    def __getitem__(self, idx):
        graph = self.graphs[idx]
        edge_labels = self.labels[idx]
        
        # Convert NetworkX graph to PyTorch Geometric format
        node_features = []
        node_mapping = {}
        
        for i, (node, data) in enumerate(graph.nodes(data=True)):
            node_mapping[node] = i
            features = [
                data.get('trust_level', 0.5),
                data.get('security_level', 0),
                data.get('exposure_score', 0),
                graph.degree(node),
                # Add more features as needed
            ]
            node_features.append(features)
        
        x = torch.tensor(node_features, dtype=torch.float)
        
        # Convert edges
        edge_list = []
        edge_label_list = []
        
        for edge in graph.edges():
            source_idx = node_mapping[edge[0]]
            target_idx = node_mapping[edge[1]]
            
            edge_list.append([source_idx, target_idx])
            
            # Check if this edge is a boundary
            is_boundary = edge in edge_labels or (edge[1], edge[0]) in edge_labels
            edge_label_list.append(1 if is_boundary else 0)
        
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        edge_labels_tensor = torch.tensor(edge_label_list, dtype=torch.long)
        
        return Data(x=x, edge_index=edge_index, edge_labels=edge_labels_tensor)

def train_gnn_boundary_detector(train_graphs, train_labels, val_graphs, val_labels, 
                               epochs=100, lr=0.01):
    """
    Train the GNN model for trust boundary detection
    """
    # Create datasets
    train_dataset = TrustBoundaryDataset(train_graphs, train_labels)
    val_dataset = TrustBoundaryDataset(val_graphs, val_labels)
    
    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    
    # Initialize model
    input_dim = 4  # Number of node features
    model = TrustBoundaryGNN(input_dim)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    
    # Training loop
    model.train()
    for epoch in range(epochs):
        total_loss = 0
        
        for batch in train_loader:
            optimizer.zero_grad()
            
            predictions = model(batch.x, batch.edge_index)
            loss = criterion(predictions, batch.edge_labels)
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
        
        if epoch % 10 == 0:
            # Validation
            model.eval()
            val_accuracy = evaluate_model(model, val_loader)
            model.train()
            
            print(f'Epoch {epoch}, Loss: {total_loss/len(train_loader):.4f}, '
                  f'Val Accuracy: {val_accuracy:.4f}')
    
    return model

def evaluate_model(model, data_loader):
    """Evaluate the model on validation/test data"""
    model.eval()
    correct = 0
    total = 0
    
    with torch.no_grad():
        for batch in data_loader:
            predictions = model(batch.x, batch.edge_index)
            predicted_labels = torch.argmax(predictions, dim=1)
            
            correct += (predicted_labels == batch.edge_labels).sum().item()
            total += batch.edge_labels.size(0)
    
    return correct / total
```

### 7.4 Reinforcement Learning for Dynamic Boundary Adaptation

#### RL Agent for Trust Boundary Optimization
```python
import gym
from gym import spaces
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env

class TrustBoundaryEnvironment(gym.Env):
    """
    Reinforcement Learning environment for dynamic trust boundary optimization
    """
    
    def __init__(self, graph, initial_boundaries):
        super(TrustBoundaryEnvironment, self).__init__()
        
        self.graph = graph
        self.current_boundaries = set(initial_boundaries)
        self.all_edges = list(graph.edges())
        
        # Action space: add/remove boundary for each edge
        self.action_space = spaces.MultiDiscrete([3] * len(self.all_edges))  # 0: no change, 1: add, 2: remove
        
        # Observation space: graph features + current boundary state
        self.observation_space = spaces.Box(
            low=0, high=1, 
            shape=(len(self.all_edges) * 5,),  # 5 features per edge
            dtype=np.float32
        )
        
        self.max_steps = 100
        self.current_step = 0
        
    def reset(self):
        """Reset the environment to initial state"""
        self.current_boundaries = set()
        self.current_step = 0
        return self._get_observation()
    
    def _get_observation(self):
        """Get current state observation"""
        obs = []
        
        # Calculate graph features
        betweenness = nx.betweenness_centrality(self.graph)
        
        for edge in self.all_edges:
            source, target = edge
            
            # Edge features
            edge_features = [
                1 if edge in self.current_boundaries else 0,  # Current boundary status
                self.graph.degree(source) / len(self.graph),  # Normalized source degree
                self.graph.degree(target) / len(self.graph),  # Normalized target degree
                betweenness[source],  # Source betweenness centrality
                betweenness[target]   # Target betweenness centrality
            ]
            
            obs.extend(edge_features)
        
        return np.array(obs, dtype=np.float32)
    
    def step(self, action):
        """Execute action and return new state, reward, done, info"""
        self.current_step += 1
        
        # Apply actions
        for i, act in enumerate(action):
            edge = self.all_edges[i]
            
            if act == 1:  # Add boundary
                self.current_boundaries.add(edge)
            elif act == 2:  # Remove boundary
                self.current_boundaries.discard(edge)
        
        # Calculate reward
        reward = self._calculate_reward()
        
        # Check if done
        done = self.current_step >= self.max_steps
        
        return self._get_observation(), reward, done, {}
    
    def _calculate_reward(self):
        """Calculate reward based on current boundary configuration"""
        # Reward components:
        # 1. Security coverage (how well boundaries protect the system)
        # 2. Operational efficiency (not too many boundaries)
        # 3. Attack surface reduction
        
        security_score = self._calculate_security_coverage()
        efficiency_score = self._calculate_efficiency()
        
        # Combine scores
        reward = 0.7 * security_score + 0.3 * efficiency_score
        
        return reward
    
    def _calculate_security_coverage(self):
        """Calculate how well current boundaries provide security coverage"""
        # Simplified security calculation
        # In practice, this would involve complex security metrics
        
        if not self.current_boundaries:
            return 0.0
        
        # Calculate coverage of critical paths
        critical_paths = self._identify_critical_paths()
        covered_paths = 0
        
        for path in critical_paths:
            if self._path_crosses_boundary(path):
                covered_paths += 1
        
        return covered_paths / len(critical_paths) if critical_paths else 0.0
    
    def _calculate_efficiency(self):
        """Calculate efficiency score (fewer boundaries is better)"""
        max_boundaries = len(self.all_edges)
        boundary_ratio = len(self.current_boundaries) / max_boundaries
        
        # Efficiency decreases as we add more boundaries
        return 1.0 - boundary_ratio
    
    def _identify_critical_paths(self):
        """Identify critical paths that should be protected by boundaries"""
        # This is a simplified implementation
        # In practice, you'd identify paths between sensitive resources
        
        critical_paths = []
        
        # Find paths between high-value nodes
        high_value_nodes = [node for node, data in self.graph.nodes(data=True) 
                           if data.get('value', 0) > 0.8]
        
        for i, source in enumerate(high_value_nodes):
            for target in high_value_nodes[i+1:]:
                try:
                    path = nx.shortest_path(self.graph, source, target)
                    if len(path) > 2:  # Only consider paths with intermediate nodes
                        critical_paths.append(path)
                except nx.NetworkXNoPath:
                    continue
        
        return critical_paths
    
    def _path_crosses_boundary(self, path):
        """Check if a path crosses any trust boundary"""
        for i in range(len(path) - 1):
            edge = (path[i], path[i+1])
            if edge in self.current_boundaries or (edge[1], edge[0]) in self.current_boundaries:
                return True
        return False

def train_rl_boundary_optimizer(graph, initial_boundaries, training_episodes=10000):
    """
    Train reinforcement learning agent for trust boundary optimization
    """
    # Create environment
    env = TrustBoundaryEnvironment(graph, initial_boundaries)
    
    # Create vectorized environment for stable-baselines3
    vec_env = make_vec_env(lambda: env, n_envs=1)
    
    # Initialize PPO agent
    model = PPO("MlpPolicy", vec_env, verbose=1)
    
    # Train the agent
    model.learn(total_timesteps=training_episodes)
    
    return model

def optimize_boundaries_with_rl(graph, initial_boundaries, trained_model):
    """
    Use trained RL agent to optimize trust boundaries
    """
    env = TrustBoundaryEnvironment(graph, initial_boundaries)
    obs = env.reset()
    
    # Run the trained model
    action, _ = trained_model.predict(obs, deterministic=True)
    obs, reward, done, info = env.step(action)
    
    return list(env.current_boundaries), reward
```

## 8. Implementation Recommendations for Threagile {#recommendations}

### 8.1 Architecture Integration Strategy

#### Proposed Integration Architecture
```
Threagile Architecture Extension:

pkg/security/
├── boundary_detection/
│   ├── graph_analyzer.go
│   ├── ml_detector.go
│   ├── cloud_pattern_detector.go
│   └── boundary_consolidator.go
├── trust_boundaries/
│   ├── boundary_types.go
│   ├── trust_calculator.go
│   └── boundary_validator.go
└── algorithms/
    ├── spectral_clustering.go
    ├── community_detection.go
    └── centrality_analysis.go
```

#### Core Interface Design
```go
// TrustBoundaryDetector defines the interface for boundary detection algorithms
type TrustBoundaryDetector interface {
    DetectBoundaries(model *types.Model) ([]TrustBoundary, error)
    GetDetectorType() DetectorType
    GetConfidence() float64
}

// TrustBoundary represents a detected trust boundary
type TrustBoundary struct {
    ID          string                 `json:"id"`
    Type        TrustBoundaryType      `json:"type"`
    Source      string                 `json:"source"`
    Target      string                 `json:"target"`
    Confidence  float64                `json:"confidence"`
    Algorithm   string                 `json:"algorithm"`
    Properties  map[string]interface{} `json:"properties"`
    Risks       []string               `json:"associated_risks"`
}

// TrustBoundaryType represents different types of trust boundaries
type TrustBoundaryType string

const (
    NetworkBoundary     TrustBoundaryType = "network"
    ApplicationBoundary TrustBoundaryType = "application"
    DataBoundary        TrustBoundaryType = "data"
    IdentityBoundary    TrustBoundaryType = "identity"
    ProcessBoundary     TrustBoundaryType = "process"
    CloudBoundary       TrustBoundaryType = "cloud"
)
```

### 8.2 Implementation Roadmap

#### Phase 1: Graph-Based Foundation
1. **System Graph Construction**
   - Convert Threagile model to graph representation
   - Implement graph analysis utilities
   - Add basic centrality calculations

```go
// pkg/security/boundary_detection/graph_analyzer.go
package boundary_detection

import (
    "github.com/threagile/threagile/pkg/types"
    "gonum.org/v1/gonum/graph"
    "gonum.org/v1/gonum/graph/simple"
)

type GraphAnalyzer struct {
    graph *simple.WeightedUndirectedGraph
    nodeMap map[string]int64
}

func NewGraphAnalyzer(model *types.Model) *GraphAnalyzer {
    g := simple.NewWeightedUndirectedGraph(0, 0)
    nodeMap := make(map[string]int64)
    
    // Add technical assets as nodes
    for assetId, asset := range model.TechnicalAssets {
        nodeId := g.NewNode().ID()
        g.AddNode(simple.Node(nodeId))
        nodeMap[assetId] = nodeId
    }
    
    // Add communication links as edges
    for _, asset := range model.TechnicalAssets {
        for targetId := range asset.CommunicationLinks {
            if sourceId, ok := nodeMap[asset.Id]; ok {
                if targetNodeId, ok := nodeMap[targetId]; ok {
                    edge := g.NewWeightedEdge(
                        simple.Node(sourceId), 
                        simple.Node(targetNodeId), 
                        1.0, // Default weight
                    )
                    g.SetWeightedEdge(edge)
                }
            }
        }
    }
    
    return &GraphAnalyzer{
        graph: g,
        nodeMap: nodeMap,
    }
}

func (ga *GraphAnalyzer) DetectBoundaries(model *types.Model) ([]TrustBoundary, error) {
    boundaries := []TrustBoundary{}
    
    // Apply multiple detection algorithms
    spectralBoundaries, err := ga.detectSpectralBoundaries()
    if err != nil {
        return nil, err
    }
    boundaries = append(boundaries, spectralBoundaries...)
    
    centralityBoundaries, err := ga.detectCentralityBoundaries()
    if err != nil {
        return nil, err
    }
    boundaries = append(boundaries, centralityBoundaries...)
    
    return boundaries, nil
}

func (ga *GraphAnalyzer) detectSpectralBoundaries() ([]TrustBoundary, error) {
    // Implement spectral clustering for boundary detection
    // This is a simplified implementation
    boundaries := []TrustBoundary{}
    
    // TODO: Implement actual spectral clustering algorithm
    // For now, return placeholder
    
    return boundaries, nil
}

func (ga *GraphAnalyzer) detectCentralityBoundaries() ([]TrustBoundary, error) {
    // Implement centrality-based boundary detection
    boundaries := []TrustBoundary{}
    
    // Calculate betweenness centrality
    // TODO: Implement actual centrality calculation
    
    return boundaries, nil
}
```

#### Phase 2: Cloud Pattern Detection
1. **Cloud-Specific Detectors**
   - AWS boundary patterns (VPC, Security Groups, IAM)
   - Azure boundary patterns (Subscriptions, NSGs, VNets)
   - GCP boundary patterns (Projects, VPCs, IAM)

```go
// pkg/security/boundary_detection/cloud_pattern_detector.go
package boundary_detection

import (
    "github.com/threagile/threagile/pkg/types"
)

type CloudPatternDetector struct {
    cloudProvider string
}

func (cpd *CloudPatternDetector) DetectBoundaries(model *types.Model) ([]TrustBoundary, error) {
    boundaries := []TrustBoundary{}
    
    // Detect VPC boundaries
    vpcBoundaries := cpd.detectVPCBoundaries(model)
    boundaries = append(boundaries, vpcBoundaries...)
    
    // Detect IAM boundaries
    iamBoundaries := cpd.detectIAMBoundaries(model)
    boundaries = append(boundaries, iamBoundaries...)
    
    // Detect security group boundaries
    sgBoundaries := cpd.detectSecurityGroupBoundaries(model)
    boundaries = append(boundaries, sgBoundaries...)
    
    return boundaries, nil
}

func (cpd *CloudPatternDetector) detectVPCBoundaries(model *types.Model) []TrustBoundary {
    boundaries := []TrustBoundary{}
    
    // Analyze trust boundaries for assets in different VPCs
    for assetId, asset := range model.TechnicalAssets {
        vpc := cpd.extractVPCFromAsset(asset)
        
        for linkTarget := range asset.CommunicationLinks {
            if targetAsset, ok := model.TechnicalAssets[linkTarget]; ok {
                targetVPC := cpd.extractVPCFromAsset(targetAsset)
                
                if vpc != targetVPC && vpc != "" && targetVPC != "" {
                    boundary := TrustBoundary{
                        ID:         assetId + "->" + linkTarget + ":vpc",
                        Type:       CloudBoundary,
                        Source:     assetId,
                        Target:     linkTarget,
                        Confidence: 0.9,
                        Algorithm:  "vpc_pattern_detection",
                        Properties: map[string]interface{}{
                            "source_vpc": vpc,
                            "target_vpc": targetVPC,
                            "boundary_type": "vpc_crossing",
                        },
                    }
                    boundaries = append(boundaries, boundary)
                }
            }
        }
    }
    
    return boundaries
}

func (cpd *CloudPatternDetector) extractVPCFromAsset(asset types.TechnicalAsset) string {
    // Extract VPC information from asset tags or properties
    if vpc, ok := asset.Tags["vpc"]; ok {
        return vpc
    }
    
    // Try to extract from other properties
    for key, value := range asset.CustomProperties {
        if key == "vpc_id" || key == "vpc" {
            if vpcStr, ok := value.(string); ok {
                return vpcStr
            }
        }
    }
    
    return ""
}
```

#### Phase 3: Machine Learning Integration
1. **Feature-Based Detection**
   - Extract features from Threagile models
   - Train boundary detection models
   - Implement online prediction

```go
// pkg/security/boundary_detection/ml_detector.go
package boundary_detection

import (
    "context"
    "encoding/json"
    "bytes"
    "net/http"
    "github.com/threagile/threagile/pkg/types"
)

type MLDetector struct {
    modelEndpoint string
    apiKey        string
}

type MLFeatures struct {
    SourceDegree          int     `json:"source_degree"`
    TargetDegree          int     `json:"target_degree"`
    DegreeDifference      int     `json:"degree_difference"`
    TrustDifferential     float64 `json:"trust_differential"`
    CommunicationFreq     int     `json:"communication_frequency"`
    DataSensitivity       int     `json:"data_sensitivity"`
    CrossTrustBoundary    bool    `json:"cross_trust_boundary"`
    NetworkDistance       int     `json:"network_distance"`
}

type MLPrediction struct {
    IsBoundary   bool    `json:"is_boundary"`
    Confidence   float64 `json:"confidence"`
    Features     MLFeatures `json:"features"`
}

func (mld *MLDetector) DetectBoundaries(model *types.Model) ([]TrustBoundary, error) {
    boundaries := []TrustBoundary{}
    
    // Extract features for each communication link
    for assetId, asset := range model.TechnicalAssets {
        for linkTarget := range asset.CommunicationLinks {
            features := mld.extractFeatures(model, assetId, linkTarget)
            
            // Call ML prediction service
            prediction, err := mld.predictBoundary(features)
            if err != nil {
                continue // Skip on error, log in production
            }
            
            if prediction.IsBoundary && prediction.Confidence > 0.7 {
                boundary := TrustBoundary{
                    ID:         assetId + "->" + linkTarget + ":ml",
                    Type:       ApplicationBoundary,
                    Source:     assetId,
                    Target:     linkTarget,
                    Confidence: prediction.Confidence,
                    Algorithm:  "ml_classifier",
                    Properties: map[string]interface{}{
                        "ml_features": prediction.Features,
                        "model_version": "1.0",
                    },
                }
                boundaries = append(boundaries, boundary)
            }
        }
    }
    
    return boundaries, nil
}

func (mld *MLDetector) extractFeatures(model *types.Model, sourceId, targetId string) MLFeatures {
    sourceAsset := model.TechnicalAssets[sourceId]
    targetAsset := model.TechnicalAssets[targetId]
    
    features := MLFeatures{
        SourceDegree:     len(sourceAsset.CommunicationLinks),
        TargetDegree:     len(targetAsset.CommunicationLinks),
        DegreeDifference: abs(len(sourceAsset.CommunicationLinks) - len(targetAsset.CommunicationLinks)),
    }
    
    // Calculate trust differential
    sourceTrust := mld.calculateTrustLevel(sourceAsset)
    targetTrust := mld.calculateTrustLevel(targetAsset)
    features.TrustDifferential = abs(sourceTrust - targetTrust)
    
    // Check if crossing existing trust boundaries
    features.CrossTrustBoundary = mld.crossesTrustBoundary(model, sourceId, targetId)
    
    // Calculate network distance (simplified)
    features.NetworkDistance = mld.calculateNetworkDistance(model, sourceId, targetId)
    
    return features
}

func (mld *MLDetector) predictBoundary(features MLFeatures) (*MLPrediction, error) {
    // Prepare request
    jsonData, err := json.Marshal(features)
    if err != nil {
        return nil, err
    }
    
    req, err := http.NewRequest("POST", mld.modelEndpoint+"/predict", bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+mld.apiKey)
    
    // Make request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    // Parse response
    var prediction MLPrediction
    err = json.NewDecoder(resp.Body).Decode(&prediction)
    if err != nil {
        return nil, err
    }
    
    return &prediction, nil
}

func abs(x int) int {
    if x < 0 {
        return -x
    }
    return x
}

func (mld *MLDetector) calculateTrustLevel(asset types.TechnicalAsset) float64 {
    // Simplified trust level calculation
    trustLevel := 0.5 // Default neutral trust
    
    // Adjust based on asset properties
    if asset.Internet {
        trustLevel -= 0.3 // Internet-facing reduces trust
    }
    
    if asset.MultiTenant {
        trustLevel -= 0.2 // Multi-tenant reduces trust
    }
    
    // Consider security technologies
    if len(asset.Technologies) > 0 {
        for _, tech := range asset.Technologies {
            if tech.HasAttribute("encryption") {
                trustLevel += 0.1
            }
            if tech.HasAttribute("authentication") {
                trustLevel += 0.1
            }
        }
    }
    
    // Clamp to [0, 1] range
    if trustLevel < 0 {
        trustLevel = 0
    }
    if trustLevel > 1 {
        trustLevel = 1
    }
    
    return trustLevel
}
```

### 8.3 Integration with Existing Risk Rules

#### Enhanced Risk Rule Framework
```go
// Enhanced risk rule that considers detected trust boundaries
type BoundaryAwareRiskRule struct {
    BaseRiskRule
    boundaryDetector TrustBoundaryDetector
}

func (barr *BoundaryAwareRiskRule) GenerateRisks(model *types.Model, 
    boundaries []TrustBoundary) []types.Risk {
    
    risks := []types.Risk{}
    
    // Generate risks based on detected boundaries
    for _, boundary := range boundaries {
        // Check for inadequate boundary protection
        if barr.isInadequatelyProtected(model, boundary) {
            risk := types.Risk{
                Category:                    "Trust Boundary Violation",
                Severity:                    types.CalculatedSeverity(boundary),
                ExploitationLikelihood:      types.Medium,
                ExploitationImpact:         types.High,
                Title:                      "Inadequate Trust Boundary Protection",
                SyntheticId:                boundary.ID + "@inadequate-protection",
                Description:                fmt.Sprintf("Trust boundary between %s and %s lacks adequate protection", boundary.Source, boundary.Target),
                DetectionAlgorithm:         boundary.Algorithm,
                BoundaryConfidence:         boundary.Confidence,
            }
            risks = append(risks, risk)
        }
        
        // Check for boundary bypasses
        bypasses := barr.detectBoundaryBypasses(model, boundary)
        for _, bypass := range bypasses {
            risk := types.Risk{
                Category:                    "Trust Boundary Bypass",
                // ... other risk properties
            }
            risks = append(risks, risk)
        }
    }
    
    return risks
}
```

### 8.4 User Interface Integration

#### Visual Boundary Representation
```go
// Add boundary visualization to diagram generation
type BoundaryVisualizer struct {
    boundaries []TrustBoundary
}

func (bv *BoundaryVisualizer) AddBoundariesToDiagram(diagram *types.DiagramData) {
    for _, boundary := range bv.boundaries {
        // Add visual boundary representation
        boundaryElement := types.DiagramElement{
            Type:        "trust_boundary",
            ID:          boundary.ID,
            Source:      boundary.Source,
            Target:      boundary.Target,
            Confidence:  boundary.Confidence,
            Algorithm:   boundary.Algorithm,
            Style:       bv.getBoundaryStyle(boundary),
        }
        
        diagram.Boundaries = append(diagram.Boundaries, boundaryElement)
    }
}

func (bv *BoundaryVisualizer) getBoundaryStyle(boundary TrustBoundary) map[string]string {
    style := map[string]string{
        "stroke": "#ff0000",
        "stroke-width": "2",
        "stroke-dasharray": "5,5",
    }
    
    // Adjust style based on confidence
    if boundary.Confidence > 0.8 {
        style["stroke"] = "#ff0000"        // High confidence: red
    } else if boundary.Confidence > 0.6 {
        style["stroke"] = "#ffa500"        // Medium confidence: orange
    } else {
        style["stroke"] = "#ffff00"        // Low confidence: yellow
    }
    
    // Adjust opacity based on confidence
    opacity := fmt.Sprintf("%.2f", boundary.Confidence)
    style["stroke-opacity"] = opacity
    
    return style
}
```

### 8.5 Configuration and Customization

#### Boundary Detection Configuration
```yaml
# threagile.yaml extension
boundary_detection:
  enabled: true
  algorithms:
    - name: "graph_spectral"
      enabled: true
      confidence_threshold: 0.7
      parameters:
        num_clusters: "auto"
        eigengap_threshold: 0.1
    
    - name: "cloud_patterns"
      enabled: true
      confidence_threshold: 0.8
      cloud_providers: ["aws", "azure", "gcp"]
      
    - name: "ml_classifier"
      enabled: false  # Requires external ML service
      endpoint: "https://ml-service.example.com"
      api_key: "${ML_API_KEY}"
      confidence_threshold: 0.75
  
  consolidation:
    enabled: true
    min_consensus: 2  # Require at least 2 algorithms to agree
    confidence_boost: 0.1  # Boost confidence for consensus boundaries
    
  visualization:
    show_in_diagrams: true
    show_confidence_levels: true
    color_by_confidence: true
```

## 9. Code Examples and Algorithms {#code-examples}

### 9.1 Complete Spectral Clustering Implementation

```python
import numpy as np
import networkx as nx
from scipy.sparse.linalg import eigsh
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt

class SpectralTrustBoundaryDetector:
    """
    Complete implementation of spectral clustering for trust boundary detection
    """
    
    def __init__(self, num_clusters=None, sigma=1.0):
        self.num_clusters = num_clusters
        self.sigma = sigma  # Parameter for Gaussian similarity
        
    def detect_boundaries(self, graph):
        """
        Main method to detect trust boundaries using spectral clustering
        """
        # Step 1: Create adjacency matrix
        adj_matrix = nx.to_numpy_array(graph)
        
        # Step 2: Create similarity matrix (Gaussian kernel)
        similarity_matrix = self._create_similarity_matrix(adj_matrix)
        
        # Step 3: Compute Laplacian matrix
        laplacian = self._compute_normalized_laplacian(similarity_matrix)
        
        # Step 4: Compute eigenvalues and eigenvectors
        if self.num_clusters is None:
            eigenvals, eigenvecs = self._compute_all_eigenvalues(laplacian)
            self.num_clusters = self._find_optimal_clusters(eigenvals)
        
        eigenvals, eigenvecs = eigsh(laplacian, k=self.num_clusters, which='SM')
        
        # Step 5: Apply k-means clustering on eigenvectors
        cluster_assignments = self._cluster_eigenvectors(eigenvecs)
        
        # Step 6: Find boundary edges
        boundaries = self._find_boundary_edges(graph, cluster_assignments)
        
        return boundaries, cluster_assignments
    
    def _create_similarity_matrix(self, adj_matrix):
        """Create similarity matrix using Gaussian kernel"""
        n = adj_matrix.shape[0]
        similarity = np.zeros((n, n))
        
        for i in range(n):
            for j in range(n):
                if adj_matrix[i, j] > 0:
                    # Use Gaussian similarity for connected nodes
                    similarity[i, j] = np.exp(-adj_matrix[i, j]**2 / (2 * self.sigma**2))
                else:
                    similarity[i, j] = 0
        
        return similarity
    
    def _compute_normalized_laplacian(self, similarity_matrix):
        """Compute normalized Laplacian matrix"""
        # Degree matrix
        degree_matrix = np.diag(np.sum(similarity_matrix, axis=1))
        
        # Avoid division by zero
        degree_sqrt_inv = np.zeros_like(degree_matrix)
        for i in range(degree_matrix.shape[0]):
            if degree_matrix[i, i] > 0:
                degree_sqrt_inv[i, i] = 1.0 / np.sqrt(degree_matrix[i, i])
        
        # Normalized Laplacian: L_norm = D^(-1/2) * L * D^(-1/2)
        # where L = D - W (unnormalized Laplacian)
        unnormalized_laplacian = degree_matrix - similarity_matrix
        normalized_laplacian = degree_sqrt_inv @ unnormalized_laplacian @ degree_sqrt_inv
        
        return normalized_laplacian
    
    def _compute_all_eigenvalues(self, laplacian):
        """Compute all eigenvalues for optimal cluster detection"""
        eigenvals, eigenvecs = np.linalg.eigh(laplacian)
        return eigenvals, eigenvecs
    
    def _find_optimal_clusters(self, eigenvals):
        """Find optimal number of clusters using eigengap heuristic"""
        # Sort eigenvalues
        eigenvals = np.sort(eigenvals)
        
        # Compute gaps between consecutive eigenvalues
        gaps = np.diff(eigenvals)
        
        # Find the largest gap (but not the first few which might be noise)
        start_idx = min(2, len(gaps) - 1)
        optimal_clusters = np.argmax(gaps[start_idx:]) + start_idx + 2
        
        return min(optimal_clusters, 10)  # Cap at reasonable number
    
    def _cluster_eigenvectors(self, eigenvecs):
        """Apply k-means clustering to eigenvectors"""
        # Use the smallest eigenvalue eigenvectors (excluding the first one)
        if self.num_clusters == 2:
            clustering_vectors = eigenvecs[:, 1:2]
        else:
            clustering_vectors = eigenvecs[:, 1:self.num_clusters]
        
        # Normalize rows
        row_norms = np.linalg.norm(clustering_vectors, axis=1)
        clustering_vectors = clustering_vectors / row_norms[:, np.newaxis]
        
        # Apply k-means
        kmeans = KMeans(n_clusters=self.num_clusters, random_state=42)
        cluster_assignments = kmeans.fit_predict(clustering_vectors)
        
        return cluster_assignments
    
    def _find_boundary_edges(self, graph, cluster_assignments):
        """Find edges that cross cluster boundaries"""
        boundaries = []
        node_list = list(graph.nodes())
        
        for edge in graph.edges():
            source_idx = node_list.index(edge[0])
            target_idx = node_list.index(edge[1])
            
            if cluster_assignments[source_idx] != cluster_assignments[target_idx]:
                boundary_info = {
                    'source': edge[0],
                    'target': edge[1],
                    'source_cluster': cluster_assignments[source_idx],
                    'target_cluster': cluster_assignments[target_idx],
                    'type': 'spectral_boundary',
                    'algorithm': 'spectral_clustering'
                }
                
                # Add edge weight if available
                if graph.has_edge(edge[0], edge[1]):
                    edge_data = graph.get_edge_data(edge[0], edge[1])
                    boundary_info['edge_weight'] = edge_data.get('weight', 1.0)
                
                boundaries.append(boundary_info)
        
        return boundaries
    
    def visualize_clusters(self, graph, cluster_assignments):
        """Visualize the graph with cluster coloring"""
        plt.figure(figsize=(12, 8))
        
        # Create position layout
        pos = nx.spring_layout(graph, k=3, iterations=50)
        
        # Color nodes by cluster
        colors = plt.cm.Set3(np.linspace(0, 1, self.num_clusters))
        node_colors = [colors[cluster_assignments[i]] 
                      for i, node in enumerate(graph.nodes())]
        
        # Draw nodes
        nx.draw_networkx_nodes(graph, pos, node_color=node_colors, 
                              node_size=300, alpha=0.7)
        
        # Draw edges
        nx.draw_networkx_edges(graph, pos, alpha=0.5)
        
        # Draw labels
        nx.draw_networkx_labels(graph, pos, font_size=10)
        
        plt.title(f'Spectral Clustering Results ({self.num_clusters} clusters)')
        plt.axis('off')
        plt.tight_layout()
        plt.show()

# Example usage
def example_spectral_boundary_detection():
    """Example of using spectral boundary detection"""
    
    # Create a sample graph representing a system architecture
    G = nx.Graph()
    
    # Add nodes (system components)
    components = ['web_server', 'app_server', 'database', 'cache', 
                 'external_api', 'user_interface', 'admin_panel', 'monitoring']
    G.add_nodes_from(components)
    
    # Add edges (communication links)
    edges = [
        ('user_interface', 'web_server', {'weight': 1.0}),
        ('web_server', 'app_server', {'weight': 1.0}),
        ('app_server', 'database', {'weight': 0.8}),
        ('app_server', 'cache', {'weight': 0.6}),
        ('app_server', 'external_api', {'weight': 0.3}),  # Lower trust
        ('admin_panel', 'web_server', {'weight': 0.5}),   # Different trust level
        ('monitoring', 'app_server', {'weight': 0.7}),
        ('monitoring', 'database', {'weight': 0.4}),
    ]
    
    for edge in edges:
        G.add_edge(edge[0], edge[1], **edge[2])
    
    # Apply spectral boundary detection
    detector = SpectralTrustBoundaryDetector(num_clusters=3)
    boundaries, clusters = detector.detect_boundaries(G)
    
    # Print results
    print("Detected Trust Boundaries:")
    for boundary in boundaries:
        print(f"  {boundary['source']} <-> {boundary['target']} "
              f"(Clusters: {boundary['source_cluster']} -> {boundary['target_cluster']})")
    
    # Visualize results
    detector.visualize_clusters(G, clusters)
    
    return boundaries, clusters

if __name__ == "__main__":
    boundaries, clusters = example_spectral_boundary_detection()
```

### 9.2 Advanced Community Detection Algorithm

```python
import networkx as nx
import numpy as np
from collections import defaultdict
import random

class ModularityOptimizationBoundaryDetector:
    """
    Advanced community detection using modularity optimization
    for trust boundary detection
    """
    
    def __init__(self, resolution=1.0, max_iterations=100, random_state=42):
        self.resolution = resolution
        self.max_iterations = max_iterations
        self.random_state = random_state
        random.seed(random_state)
        np.random.seed(random_state)
        
    def detect_boundaries(self, graph):
        """
        Detect trust boundaries using advanced modularity optimization
        """
        # Phase 1: Initial community assignment
        communities = self._initialize_communities(graph)
        
        # Phase 2: Modularity optimization
        communities = self._optimize_modularity(graph, communities)
        
        # Phase 3: Hierarchical merging
        communities = self._hierarchical_merge(graph, communities)
        
        # Phase 4: Extract boundaries
        boundaries = self._extract_boundaries(graph, communities)
        
        return boundaries, communities
    
    def _initialize_communities(self, graph):
        """Initialize each node in its own community"""
        communities = {}
        for i, node in enumerate(graph.nodes()):
            communities[node] = i
        return communities
    
    def _optimize_modularity(self, graph, communities):
        """Optimize modularity using local moving heuristic"""
        improved = True
        iteration = 0
        
        while improved and iteration < self.max_iterations:
            improved = False
            nodes = list(graph.nodes())
            random.shuffle(nodes)  # Randomize order
            
            for node in nodes:
                current_community = communities[node]
                best_community = current_community
                best_gain = 0.0
                
                # Calculate current modularity contribution
                current_modularity = self._calculate_node_modularity(
                    graph, node, current_community, communities
                )
                
                # Try moving node to neighboring communities
                neighboring_communities = set()
                for neighbor in graph.neighbors(node):
                    neighboring_communities.add(communities[neighbor])
                
                for candidate_community in neighboring_communities:
                    if candidate_community != current_community:
                        # Calculate modularity gain from moving
                        communities[node] = candidate_community
                        new_modularity = self._calculate_node_modularity(
                            graph, node, candidate_community, communities
                        )
                        
                        gain = new_modularity - current_modularity
                        
                        if gain > best_gain:
                            best_gain = gain
                            best_community = candidate_community
                        
                        # Restore original community
                        communities[node] = current_community
                
                # Move node if improvement found
                if best_gain > 0 and best_community != current_community:
                    communities[node] = best_community
                    improved = True
            
            iteration += 1
        
        return communities
    
    def _calculate_node_modularity(self, graph, node, community, communities):
        """Calculate modularity contribution of a node in a community"""
        m = graph.number_of_edges()
        if m == 0:
            return 0.0
        
        # Internal degree (edges to same community)
        k_in = 0
        # Total degree
        k_total = graph.degree(node)
        
        # Community total degree
        community_degree = 0
        
        for neighbor in graph.neighbors(node):
            if communities[neighbor] == community:
                k_in += 1
        
        # Calculate total degree of community
        for other_node in graph.nodes():
            if communities[other_node] == community:
                community_degree += graph.degree(other_node)
        
        # Modularity formula: (k_in / 2m) - (k_total * community_degree / (2m)^2)
        modularity = (k_in / (2 * m)) - self.resolution * (k_total * community_degree / (4 * m * m))
        
        return modularity
    
    def _hierarchical_merge(self, graph, communities):
        """Hierarchically merge communities based on modularity gain"""
        # Create community graph
        community_graph = self._create_community_graph(graph, communities)
        
        # Iteratively merge communities
        merged = True
        while merged and len(set(communities.values())) > 2:
            merged = False
            best_merge = None
            best_gain = 0.0
            
            community_list = list(set(communities.values()))
            
            for i, comm1 in enumerate(community_list):
                for comm2 in community_list[i+1:]:
                    # Calculate gain from merging comm1 and comm2
                    gain = self._calculate_merge_gain(graph, communities, comm1, comm2)
                    
                    if gain > best_gain:
                        best_gain = gain
                        best_merge = (comm1, comm2)
            
            # Perform best merge if beneficial
            if best_merge is not None and best_gain > 0:
                self._merge_communities(communities, best_merge[0], best_merge[1])
                merged = True
        
        return communities
    
    def _create_community_graph(self, graph, communities):
        """Create a graph where nodes are communities"""
        community_graph = nx.Graph()
        
        # Add community nodes
        unique_communities = set(communities.values())
        community_graph.add_nodes_from(unique_communities)
        
        # Add edges between communities
        community_edges = defaultdict(int)
        
        for edge in graph.edges():
            comm1 = communities[edge[0]]
            comm2 = communities[edge[1]]
            
            if comm1 != comm2:
                key = tuple(sorted([comm1, comm2]))
                community_edges[key] += 1
        
        for (comm1, comm2), weight in community_edges.items():
            community_graph.add_edge(comm1, comm2, weight=weight)
        
        return community_graph
    
    def _calculate_merge_gain(self, graph, communities, comm1, comm2):
        """Calculate modularity gain from merging two communities"""
        # This is a simplified calculation
        # In practice, you'd want a more sophisticated implementation
        
        m = graph.number_of_edges()
        if m == 0:
            return 0.0
        
        # Count edges between communities
        edges_between = 0
        for edge in graph.edges():
            node1, node2 = edge
            if ((communities[node1] == comm1 and communities[node2] == comm2) or
                (communities[node1] == comm2 and communities[node2] == comm1)):
                edges_between += 1
        
        # Calculate degree sums
        degree_comm1 = sum(graph.degree(node) for node in graph.nodes() 
                          if communities[node] == comm1)
        degree_comm2 = sum(graph.degree(node) for node in graph.nodes() 
                          if communities[node] == comm2)
        
        # Modularity gain formula
        gain = (edges_between / m) - self.resolution * (degree_comm1 * degree_comm2 / (2 * m * m))
        
        return gain
    
    def _merge_communities(self, communities, comm1, comm2):
        """Merge comm2 into comm1"""
        for node in communities:
            if communities[node] == comm2:
                communities[node] = comm1
    
    def _extract_boundaries(self, graph, communities):
        """Extract trust boundaries from community structure"""
        boundaries = []
        
        for edge in graph.edges():
            source, target = edge
            
            if communities[source] != communities[target]:
                boundary = {
                    'source': source,
                    'target': target,
                    'source_community': communities[source],
                    'target_community': communities[target],
                    'type': 'modularity_boundary',
                    'algorithm': 'modularity_optimization'
                }
                
                # Add edge attributes if available
                edge_data = graph.get_edge_data(source, target)
                if edge_data:
                    boundary.update(edge_data)
                
                boundaries.append(boundary)
        
        return boundaries
    
    def calculate_modularity(self, graph, communities):
        """Calculate overall modularity of the community structure"""
        if graph.number_of_edges() == 0:
            return 0.0
        
        m = graph.number_of_edges()
        modularity = 0.0
        
        for edge in graph.edges():
            node1, node2 = edge
            
            # A_ij (1 if edge exists, 0 otherwise)
            A_ij = 1.0
            
            # Expected number of edges between nodes in random graph
            k_i = graph.degree(node1)
            k_j = graph.degree(node2)
            expected = k_i * k_j / (2.0 * m)
            
            # Delta function (1 if same community, 0 otherwise)
            delta = 1.0 if communities[node1] == communities[node2] else 0.0
            
            modularity += (A_ij - self.resolution * expected) * delta
        
        return modularity / (2.0 * m)

# Example usage
def example_modularity_boundary_detection():
    """Example of using modularity optimization for boundary detection"""
    
    # Create a more complex graph with multiple natural communities
    G = nx.Graph()
    
    # Add nodes representing different system layers
    web_layer = ['nginx', 'apache', 'load_balancer']
    app_layer = ['app_server1', 'app_server2', 'api_gateway']
    data_layer = ['mysql', 'redis', 'elasticsearch']
    external = ['payment_service', 'email_service', 'monitoring']
    
    all_nodes = web_layer + app_layer + data_layer + external
    G.add_nodes_from(all_nodes)
    
    # Add edges within layers (high connectivity)
    layer_edges = []
    
    # Web layer internal connections
    for i, node1 in enumerate(web_layer):
        for node2 in web_layer[i+1:]:
            layer_edges.append((node1, node2, {'weight': 1.0, 'layer': 'web'}))
    
    # App layer internal connections
    for i, node1 in enumerate(app_layer):
        for node2 in app_layer[i+1:]:
            layer_edges.append((node1, node2, {'weight': 1.0, 'layer': 'app'}))
    
    # Data layer internal connections
    for i, node1 in enumerate(data_layer):
        for node2 in data_layer[i+1:]:
            layer_edges.append((node1, node2, {'weight': 0.8, 'layer': 'data'}))
    
    # Cross-layer connections (trust boundaries)
    cross_layer_edges = [
        ('nginx', 'app_server1', {'weight': 0.9, 'type': 'cross_layer'}),
        ('load_balancer', 'api_gateway', {'weight': 0.9, 'type': 'cross_layer'}),
        ('app_server1', 'mysql', {'weight': 0.7, 'type': 'cross_layer'}),
        ('app_server2', 'redis', {'weight': 0.7, 'type': 'cross_layer'}),
        ('api_gateway', 'elasticsearch', {'weight': 0.6, 'type': 'cross_layer'}),
        ('app_server1', 'payment_service', {'weight': 0.3, 'type': 'external'}),
        ('app_server2', 'email_service', {'weight': 0.4, 'type': 'external'}),
        ('monitoring', 'nginx', {'weight': 0.5, 'type': 'monitoring'}),
        ('monitoring', 'mysql', {'weight': 0.5, 'type': 'monitoring'}),
    ]
    
    all_edges = layer_edges + cross_layer_edges
    
    for edge in all_edges:
        G.add_edge(edge[0], edge[1], **edge[2])
    
    # Apply modularity optimization boundary detection
    detector = ModularityOptimizationBoundaryDetector(resolution=1.0)
    boundaries, communities = detector.detect_boundaries(G)
    
    # Calculate overall modularity
    modularity = detector.calculate_modularity(G, communities)
    
    # Print results
    print(f"Overall Modularity: {modularity:.3f}")
    print(f"Number of Communities: {len(set(communities.values()))}")
    print("\nCommunity Assignments:")
    
    community_groups = defaultdict(list)
    for node, comm in communities.items():
        community_groups[comm].append(node)
    
    for comm, nodes in community_groups.items():
        print(f"  Community {comm}: {nodes}")
    
    print("\nDetected Trust Boundaries:")
    for boundary in boundaries:
        print(f"  {boundary['source']} <-> {boundary['target']} "
              f"(Communities: {boundary['source_community']} -> {boundary['target_community']})")
    
    return boundaries, communities, modularity

if __name__ == "__main__":
    boundaries, communities, modularity = example_modularity_boundary_detection()
```

### 9.3 Multi-Algorithm Boundary Consensus

```python
import networkx as nx
import numpy as np
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple
from enum import Enum

class BoundaryAlgorithmType(Enum):
    SPECTRAL_CLUSTERING = "spectral_clustering"
    MODULARITY_OPTIMIZATION = "modularity_optimization"
    BETWEENNESS_CENTRALITY = "betweenness_centrality"
    EDGE_BETWEENNESS = "edge_betweenness"
    MINIMUM_CUT = "minimum_cut"

@dataclass
class BoundaryDetection:
    """Represents a boundary detected by an algorithm"""
    source: str
    target: str
    algorithm: BoundaryAlgorithmType
    confidence: float
    properties: Dict

class ConsensuseBoundaryDetector:
    """
    Multi-algorithm consensus-based trust boundary detector
    """
    
    def __init__(self, algorithms=None, consensus_threshold=0.5, 
                 weight_strategy='uniform'):
        """
        Initialize consensus detector
        
        Args:
            algorithms: List of algorithms to use
            consensus_threshold: Minimum agreement ratio for boundary acceptance
            weight_strategy: How to weight different algorithms ('uniform', 'confidence', 'custom')
        """
        self.algorithms = algorithms or [
            BoundaryAlgorithmType.SPECTRAL_CLUSTERING,
            BoundaryAlgorithmType.MODULARITY_OPTIMIZATION,
            BoundaryAlgorithmType.BETWEENNESS_CENTRALITY,
            BoundaryAlgorithmType.EDGE_BETWEENNESS
        ]
        
        self.consensus_threshold = consensus_threshold
        self.weight_strategy = weight_strategy
        
        # Algorithm weights (can be customized)
        self.algorithm_weights = {
            BoundaryAlgorithmType.SPECTRAL_CLUSTERING: 1.0,
            BoundaryAlgorithmType.MODULARITY_OPTIMIZATION: 1.0,
            BoundaryAlgorithmType.BETWEENNESS_CENTRALITY: 0.8,
            BoundaryAlgorithmType.EDGE_BETWEENNESS: 0.9,
            BoundaryAlgorithmType.MINIMUM_CUT: 0.7
        }
    
    def detect_boundaries(self, graph):
        """
        Detect trust boundaries using consensus from multiple algorithms
        """
        # Step 1: Run all algorithms
        all_detections = []
        
        for algorithm in self.algorithms:
            try:
                detections = self._run_algorithm(graph, algorithm)
                all_detections.extend(detections)
            except Exception as e:
                print(f"Warning: Algorithm {algorithm} failed: {e}")
                continue
        
        # Step 2: Build consensus
        consensus_boundaries = self._build_consensus(all_detections)
        
        # Step 3: Rank boundaries by consensus strength
        ranked_boundaries = self._rank_boundaries(consensus_boundaries)
        
        return ranked_boundaries
    
    def _run_algorithm(self, graph, algorithm_type):
        """Run a specific boundary detection algorithm"""
        detections = []
        
        if algorithm_type == BoundaryAlgorithmType.SPECTRAL_CLUSTERING:
            detections = self._spectral_clustering_detection(graph)
            
        elif algorithm_type == BoundaryAlgorithmType.MODULARITY_OPTIMIZATION:
            detections = self._modularity_detection(graph)
            
        elif algorithm_type == BoundaryAlgorithmType.BETWEENNESS_CENTRALITY:
            detections = self._betweenness_centrality_detection(graph)
            
        elif algorithm_type == BoundaryAlgorithmType.EDGE_BETWEENNESS:
            detections = self._edge_betweenness_detection(graph)
            
        elif algorithm_type == BoundaryAlgorithmType.MINIMUM_CUT:
            detections = self._minimum_cut_detection(graph)
        
        return detections
    
    def _spectral_clustering_detection(self, graph):
        """Spectral clustering boundary detection"""
        from sklearn.cluster import SpectralClustering
        
        if len(graph.nodes()) < 3:
            return []
        
        # Convert graph to adjacency matrix
        adj_matrix = nx.to_numpy_array(graph)
        node_list = list(graph.nodes())
        
        # Apply spectral clustering
        n_clusters = min(max(2, len(graph.nodes()) // 3), 10)
        spectral = SpectralClustering(n_clusters=n_clusters, random_state=42)
        
        try:
            cluster_labels = spectral.fit_predict(adj_matrix)
        except:
            return []
        
        # Find boundary edges
        detections = []
        for edge in graph.edges():
            source_idx = node_list.index(edge[0])
            target_idx = node_list.index(edge[1])
            
            if cluster_labels[source_idx] != cluster_labels[target_idx]:
                detection = BoundaryDetection(
                    source=edge[0],
                    target=edge[1],
                    algorithm=BoundaryAlgorithmType.SPECTRAL_CLUSTERING,
                    confidence=0.8,
                    properties={
                        'source_cluster': cluster_labels[source_idx],
                        'target_cluster': cluster_labels[target_idx]
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _modularity_detection(self, graph):
        """Modularity-based community detection"""
        try:
            communities = nx.community.greedy_modularity_communities(graph)
        except:
            return []
        
        # Create node-to-community mapping
        node_to_community = {}
        for i, community in enumerate(communities):
            for node in community:
                node_to_community[node] = i
        
        # Find boundary edges
        detections = []
        for edge in graph.edges():
            source_comm = node_to_community.get(edge[0])
            target_comm = node_to_community.get(edge[1])
            
            if source_comm is not None and target_comm is not None and source_comm != target_comm:
                detection = BoundaryDetection(
                    source=edge[0],
                    target=edge[1],
                    algorithm=BoundaryAlgorithmType.MODULARITY_OPTIMIZATION,
                    confidence=0.85,
                    properties={
                        'source_community': source_comm,
                        'target_community': target_comm,
                        'modularity': nx.community.modularity(graph, communities)
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _betweenness_centrality_detection(self, graph):
        """Betweenness centrality based boundary detection"""
        betweenness = nx.betweenness_centrality(graph)
        
        # Find nodes with high betweenness centrality (boundary candidates)
        threshold = np.percentile(list(betweenness.values()), 80)
        boundary_nodes = {node for node, centrality in betweenness.items() 
                         if centrality > threshold}
        
        detections = []
        for node in boundary_nodes:
            for neighbor in graph.neighbors(node):
                if neighbor not in boundary_nodes:
                    # Edge from high-centrality to low-centrality node
                    detection = BoundaryDetection(
                        source=node,
                        target=neighbor,
                        algorithm=BoundaryAlgorithmType.BETWEENNESS_CENTRALITY,
                        confidence=min(0.9, betweenness[node] + 0.1),
                        properties={
                            'source_centrality': betweenness[node],
                            'target_centrality': betweenness[neighbor]
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def _edge_betweenness_detection(self, graph):
        """Edge betweenness centrality based detection"""
        edge_betweenness = nx.edge_betweenness_centrality(graph)
        
        # Find edges with high betweenness (likely boundaries)
        threshold = np.percentile(list(edge_betweenness.values()), 75)
        
        detections = []
        for edge, centrality in edge_betweenness.items():
            if centrality > threshold:
                detection = BoundaryDetection(
                    source=edge[0],
                    target=edge[1],
                    algorithm=BoundaryAlgorithmType.EDGE_BETWEENNESS,
                    confidence=min(0.95, centrality + 0.05),
                    properties={
                        'edge_betweenness': centrality
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _minimum_cut_detection(self, graph):
        """Minimum cut based boundary detection"""
        detections = []
        
        # Find natural source/sink candidates
        degree_centrality = nx.degree_centrality(graph)
        nodes_by_degree = sorted(degree_centrality.items(), key=lambda x: x[1])
        
        # Use lowest and highest degree nodes as source/sink
        if len(nodes_by_degree) >= 2:
            source_candidate = nodes_by_degree[0][0]
            sink_candidate = nodes_by_degree[-1][0]
            
            try:
                cut_value, partition = nx.minimum_cut(graph, source_candidate, sink_candidate)
                source_partition, sink_partition = partition
                
                # Find edges crossing the cut
                for node in source_partition:
                    for neighbor in graph.neighbors(node):
                        if neighbor in sink_partition:
                            detection = BoundaryDetection(
                                source=node,
                                target=neighbor,
                                algorithm=BoundaryAlgorithmType.MINIMUM_CUT,
                                confidence=0.7,
                                properties={
                                    'cut_value': cut_value,
                                    'source_partition_size': len(source_partition),
                                    'sink_partition_size': len(sink_partition)
                                }
                            )
                            detections.append(detection)
                            
            except:
                pass  # Skip if minimum cut fails
        
        return detections
    
    def _build_consensus(self, all_detections):
        """Build consensus from all algorithm detections"""
        # Group detections by edge (considering both directions as same edge)
        edge_detections = defaultdict(list)
        
        for detection in all_detections:
            # Normalize edge direction
            edge_key = tuple(sorted([detection.source, detection.target]))
            edge_detections[edge_key].append(detection)
        
        consensus_boundaries = {}
        
        for edge_key, detections in edge_detections.items():
            # Calculate consensus metrics
            algorithm_count = len(detections)
            total_algorithms = len(self.algorithms)
            
            agreement_ratio = algorithm_count / total_algorithms
            
            # Only consider boundaries with sufficient agreement
            if agreement_ratio >= self.consensus_threshold:
                # Calculate weighted confidence
                if self.weight_strategy == 'uniform':
                    consensus_confidence = np.mean([d.confidence for d in detections])
                    
                elif self.weight_strategy == 'confidence':
                    weights = [d.confidence for d in detections]
                    consensus_confidence = np.average([d.confidence for d in detections], weights=weights)
                    
                elif self.weight_strategy == 'custom':
                    weights = [self.algorithm_weights[d.algorithm] for d in detections]
                    consensus_confidence = np.average([d.confidence for d in detections], weights=weights)
                
                else:
                    consensus_confidence = np.mean([d.confidence for d in detections])
                
                # Boost confidence for higher consensus
                consensus_confidence *= (1.0 + 0.2 * (agreement_ratio - self.consensus_threshold))
                consensus_confidence = min(1.0, consensus_confidence)
                
                consensus_boundaries[edge_key] = {
                    'source': edge_key[0],
                    'target': edge_key[1],
                    'consensus_confidence': consensus_confidence,
                    'agreement_ratio': agreement_ratio,
                    'supporting_algorithms': [d.algorithm for d in detections],
                    'algorithm_confidences': {d.algorithm: d.confidence for d in detections},
                    'combined_properties': self._combine_properties([d.properties for d in detections])
                }
        
        return consensus_boundaries
    
    def _combine_properties(self, properties_list):
        """Combine properties from multiple detections"""
        combined = {}
        
        # Collect all unique keys
        all_keys = set()
        for props in properties_list:
            all_keys.update(props.keys())
        
        # Combine properties
        for key in all_keys:
            values = [props.get(key) for props in properties_list if key in props]
            
            if all(isinstance(v, (int, float)) for v in values):
                # Numeric values: take average
                combined[key] = np.mean(values)
            else:
                # Non-numeric: collect unique values
                unique_values = list(set(str(v) for v in values))
                combined[key] = unique_values if len(unique_values) > 1 else unique_values[0]
        
        return combined
    
    def _rank_boundaries(self, consensus_boundaries):
        """Rank boundaries by consensus strength and confidence"""
        boundaries_list = []
        
        for edge_key, boundary_info in consensus_boundaries.items():
            # Calculate overall score
            score = (boundary_info['consensus_confidence'] * 0.7 + 
                    boundary_info['agreement_ratio'] * 0.3)
            
            boundary_info['overall_score'] = score
            boundaries_list.append(boundary_info)
        
        # Sort by overall score (descending)
        boundaries_list.sort(key=lambda x: x['overall_score'], reverse=True)
        
        return boundaries_list
    
    def analyze_consensus_quality(self, boundaries):
        """Analyze the quality of consensus results"""
        if not boundaries:
            return {}
        
        analysis = {
            'total_boundaries': len(boundaries),
            'high_confidence_boundaries': len([b for b in boundaries if b['consensus_confidence'] > 0.8]),
            'full_consensus_boundaries': len([b for b in boundaries if b['agreement_ratio'] == 1.0]),
            'average_confidence': np.mean([b['consensus_confidence'] for b in boundaries]),
            'average_agreement': np.mean([b['agreement_ratio'] for b in boundaries]),
            'algorithm_participation': Counter()
        }
        
        # Analyze algorithm participation
        for boundary in boundaries:
            for algorithm in boundary['supporting_algorithms']:
                analysis['algorithm_participation'][algorithm] += 1
        
        return analysis

# Example usage
def example_consensus_boundary_detection():
    """Example of using consensus-based boundary detection"""
    
    # Create a complex graph representing a microservices architecture
    G = nx.Graph()
    
    # Define microservices
    services = {
        'user_service': {'layer': 'business', 'sensitivity': 'medium'},
        'auth_service': {'layer': 'security', 'sensitivity': 'high'},
        'payment_service': {'layer': 'business', 'sensitivity': 'high'},
        'inventory_service': {'layer': 'business', 'sensitivity': 'medium'},
        'notification_service': {'layer': 'infrastructure', 'sensitivity': 'low'},
        'api_gateway': {'layer': 'infrastructure', 'sensitivity': 'medium'},
        'user_db': {'layer': 'data', 'sensitivity': 'high'},
        'payment_db': {'layer': 'data', 'sensitivity': 'high'},
        'inventory_db': {'layer': 'data', 'sensitivity': 'medium'},
        'cache': {'layer': 'infrastructure', 'sensitivity': 'low'},
        'message_queue': {'layer': 'infrastructure', 'sensitivity': 'low'},
        'monitoring': {'layer': 'operations', 'sensitivity': 'low'},
        'external_payment_provider': {'layer': 'external', 'sensitivity': 'high'},
        'external_email_service': {'layer': 'external', 'sensitivity': 'low'}
    }
    
    # Add nodes with attributes
    for service, attributes in services.items():
        G.add_node(service, **attributes)
    
    # Define connections with trust levels
    connections = [
        # Internal service connections
        ('api_gateway', 'user_service', {'weight': 1.0, 'trust': 'high'}),
        ('api_gateway', 'auth_service', {'weight': 1.0, 'trust': 'high'}),
        ('api_gateway', 'payment_service', {'weight': 1.0, 'trust': 'high'}),
        ('api_gateway', 'inventory_service', {'weight': 1.0, 'trust': 'high'}),
        
        # Service to database connections
        ('user_service', 'user_db', {'weight': 0.9, 'trust': 'high'}),
        ('payment_service', 'payment_db', {'weight': 0.9, 'trust': 'high'}),
        ('inventory_service', 'inventory_db', {'weight': 0.9, 'trust': 'high'}),
        
        # Service to infrastructure connections
        ('user_service', 'cache', {'weight': 0.8, 'trust': 'medium'}),
        ('inventory_service', 'cache', {'weight': 0.8, 'trust': 'medium'}),
        ('notification_service', 'message_queue', {'weight': 0.8, 'trust': 'medium'}),
        
        # Cross-service communications
        ('user_service', 'notification_service', {'weight': 0.7, 'trust': 'medium'}),
        ('payment_service', 'user_service', {'weight': 0.6, 'trust': 'medium'}),
        ('inventory_service', 'notification_service', {'weight': 0.6, 'trust': 'medium'}),
        
        # External connections (potential trust boundaries)
        ('payment_service', 'external_payment_provider', {'weight': 0.3, 'trust': 'low'}),
        ('notification_service', 'external_email_service', {'weight': 0.4, 'trust': 'low'}),
        
        # Monitoring connections (cross-cutting)
        ('monitoring', 'api_gateway', {'weight': 0.5, 'trust': 'medium'}),
        ('monitoring', 'user_db', {'weight': 0.5, 'trust': 'medium'}),
        ('monitoring', 'payment_db', {'weight': 0.5, 'trust': 'medium'}),
        
        # Authentication service connections (special trust)
        ('auth_service', 'user_db', {'weight': 0.8, 'trust': 'high'}),
        ('user_service', 'auth_service', {'weight': 0.8, 'trust': 'high'}),
        ('payment_service', 'auth_service', {'weight': 0.8, 'trust': 'high'}),
    ]
    
    # Add edges
    for source, target, attributes in connections:
        G.add_edge(source, target, **attributes)
    
    # Initialize consensus detector
    detector = ConsensuseBoundaryDetector(
        consensus_threshold=0.4,  # Require at least 40% of algorithms to agree
        weight_strategy='confidence'
    )
    
    # Detect boundaries
    print("Running consensus boundary detection...")
    boundaries = detector.detect_boundaries(G)
    
    # Analyze results
    analysis = detector.analyze_consensus_quality(boundaries)
    
    print(f"\n=== Consensus Analysis ===")
    print(f"Total boundaries detected: {analysis['total_boundaries']}")
    print(f"High confidence boundaries: {analysis['high_confidence_boundaries']}")
    print(f"Full consensus boundaries: {analysis['full_consensus_boundaries']}")
    print(f"Average confidence: {analysis['average_confidence']:.3f}")
    print(f"Average agreement: {analysis['average_agreement']:.3f}")
    
    print(f"\n=== Algorithm Participation ===")
    for algorithm, count in analysis['algorithm_participation'].most_common():
        print(f"  {algorithm.value}: {count} boundaries")
    
    print(f"\n=== Top 10 Trust Boundaries (by consensus) ===")
    for i, boundary in enumerate(boundaries[:10]):
        print(f"{i+1}. {boundary['source']} <-> {boundary['target']}")
        print(f"   Confidence: {boundary['consensus_confidence']:.3f}, "
              f"Agreement: {boundary['agreement_ratio']:.3f}")
        print(f"   Supporting algorithms: {[alg.value for alg in boundary['supporting_algorithms']]}")
        print()
    
    return boundaries, analysis

if __name__ == "__main__":
    boundaries, analysis = example_consensus_boundary_detection()
```

## 10. Future Research Directions {#future-directions}

### 10.1 Emerging Technologies and Trust Boundaries

#### Zero Trust Architecture Evolution
- **Dynamic Trust Boundaries**: Research into trust boundaries that adapt in real-time based on threat intelligence and behavioral analysis
- **Context-Aware Boundaries**: Integration of contextual information (time, location, device state) into boundary detection algorithms
- **Continuous Verification**: Algorithms that continuously re-evaluate and adjust trust boundaries

#### Cloud-Native and Serverless Architectures
- **Function-Level Boundaries**: Trust boundary detection for serverless functions and microservices
- **Container Security Boundaries**: Advanced detection of container isolation boundaries and security contexts
- **Service Mesh Integration**: Trust boundary detection integrated with service mesh technologies (Istio, Linkerd)

#### Edge Computing Trust Boundaries
- **Edge-Cloud Boundary Detection**: Algorithms specifically designed for edge computing scenarios
- **IoT Device Boundaries**: Trust boundary detection for Internet of Things ecosystems
- **Mobile Edge Computing**: Boundary detection for mobile and distributed edge scenarios

### 10.2 Advanced AI and Machine Learning Applications

#### Federated Learning for Boundary Detection
- **Privacy-Preserving Detection**: Using federated learning to train boundary detection models without sharing sensitive architectural data
- **Cross-Organization Learning**: Collaborative learning across organizations while maintaining data privacy
- **Decentralized Model Updates**: Distributed algorithms that improve boundary detection across multiple environments

#### Explainable AI for Trust Boundaries
- **Interpretable Boundary Decisions**: Research into making ML-based boundary detection decisions more interpretable
- **Causal Inference**: Understanding causal relationships in trust boundary formation
- **Human-AI Collaboration**: Interactive systems where human experts can guide and refine AI boundary detection

#### Advanced Deep Learning Architectures
- **Transformer Models for Graphs**: Applying transformer architectures to graph-based boundary detection
- **Graph Attention Networks**: Advanced attention mechanisms for identifying important boundary features
- **Multi-Modal Learning**: Combining network topology, configuration data, and behavioral information

### 10.3 Quantum Computing and Trust Boundaries

#### Quantum-Resistant Boundary Detection
- **Post-Quantum Cryptographic Boundaries**: Trust boundaries in quantum-resistant cryptographic systems
- **Quantum Key Distribution Networks**: Boundary detection for quantum communication networks
- **Hybrid Classical-Quantum Systems**: Trust boundaries in systems combining classical and quantum components

#### Quantum Algorithm Applications
- **Quantum Machine Learning**: Potential applications of quantum ML algorithms to boundary detection
- **Quantum Graph Algorithms**: Quantum speedups for graph-based boundary detection problems
- **Quantum Optimization**: Using quantum annealing for trust boundary optimization problems

### 10.4 Blockchain and Distributed Ledger Technologies

#### Decentralized Trust Models
- **Blockchain-Based Trust**: Trust boundaries in blockchain and distributed ledger systems
- **Smart Contract Boundaries**: Detection of trust boundaries in smart contract systems
- **Consensus Mechanism Boundaries**: Trust boundaries related to different consensus mechanisms

#### Cross-Chain Trust Boundaries
- **Interoperability Protocols**: Trust boundaries between different blockchain networks
- **Bridge Security**: Detection of trust boundaries in cross-chain bridges and protocols
- **Layer 2 Solutions**: Trust boundaries in layer 2 scaling solutions

### 10.5 Biological and Bio-Inspired Approaches

#### Immune System Models
- **Artificial Immune Systems**: Bio-inspired approaches to trust boundary detection based on biological immune systems
- **Self/Non-Self Recognition**: Algorithms that distinguish between trusted and untrusted components
- **Adaptive Immune Response**: Dynamic boundary adaptation based on biological immune system principles

#### Swarm Intelligence
- **Ant Colony Optimization**: Using swarm intelligence for trust boundary optimization
- **Particle Swarm Optimization**: Collective intelligence approaches to boundary detection
- **Emergent Boundary Formation**: Self-organizing trust boundaries in distributed systems

### 10.6 Advanced Graph Theory and Network Science

#### Temporal and Dynamic Networks
- **Time-Evolving Boundaries**: Trust boundaries that change over time based on system evolution
- **Dynamic Graph Analysis**: Algorithms for boundary detection in time-varying networks
- **Temporal Centrality Measures**: New centrality measures that consider temporal aspects

#### Multilayer and Multiplex Networks
- **Cross-Layer Boundary Analysis**: Trust boundaries spanning multiple network layers
- **Interdependent Networks**: Boundary detection in systems with network dependencies
- **Network of Networks**: Trust boundaries in interconnected network systems

#### Higher-Order Network Structures
- **Hypergraph Boundaries**: Trust boundaries in systems represented as hypergraphs
- **Simplicial Complexes**: Higher-order interactions and their impact on trust boundaries
- **Network Motifs**: Pattern-based boundary detection using network motifs

### 10.7 Privacy and Security Implications

#### Privacy-Preserving Boundary Detection
- **Differential Privacy**: Boundary detection algorithms that preserve privacy of system architecture
- **Secure Multi-Party Computation**: Collaborative boundary detection without revealing sensitive information
- **Homomorphic Encryption**: Performing boundary detection on encrypted system models

#### Adversarial Boundary Manipulation
- **Boundary Spoofing**: Research into how attackers might manipulate trust boundary detection
- **Resilient Detection**: Algorithms robust against adversarial manipulation of system topology
- **Deception Detection**: Identifying artificially created or manipulated trust boundaries

### 10.8 Integration with Existing Security Frameworks

#### MITRE ATT&CK Integration
- **Tactic-Specific Boundaries**: Trust boundaries tailored to specific MITRE ATT&CK tactics
- **Technique-Based Detection**: Boundary detection based on specific attack techniques
- **Adversary Behavior Modeling**: Trust boundaries informed by adversary behavior patterns

#### NIST Cybersecurity Framework
- **Framework Integration**: Aligning trust boundary detection with NIST CSF categories
- **Risk Assessment Integration**: Connecting boundary detection with risk assessment processes
- **Compliance Automation**: Automated boundary detection for compliance reporting

#### ISO 27001/27002 Alignment
- **Control-Based Boundaries**: Trust boundaries aligned with ISO 27002 security controls
- **Risk Management Integration**: Boundary detection integrated with ISO 27001 risk management
- **Audit Support**: Trust boundary detection supporting security audits

### 10.9 Standardization and Interoperability

#### Industry Standards Development
- **Boundary Detection Standards**: Development of industry standards for trust boundary detection
- **Interoperability Protocols**: Standards for sharing boundary information between tools
- **Benchmarking Frameworks**: Standardized benchmarks for evaluating boundary detection algorithms

#### Open Source Ecosystem
- **Common Libraries**: Development of standardized libraries for boundary detection algorithms
- **Dataset Sharing**: Creation of anonymized datasets for algorithm development and evaluation
- **Community Collaboration**: Foster community-driven development of boundary detection tools

### 10.10 Performance and Scalability Research

#### Distributed Algorithm Development
- **Massively Parallel Processing**: Algorithms designed for massive parallel processing systems
- **Stream Processing**: Real-time boundary detection on streaming network data
- **Edge Processing**: Lightweight algorithms suitable for edge computing devices

#### Approximation Algorithms
- **Near-Optimal Solutions**: Approximation algorithms for large-scale boundary detection
- **Sampling-Based Methods**: Statistical sampling approaches for boundary detection in large networks
- **Hierarchical Detection**: Multi-level approaches for scalable boundary detection

### 10.11 Validation and Evaluation Methodologies

#### Synthetic Dataset Generation
- **Realistic System Models**: Generation of synthetic but realistic system architectures for testing
- **Ground Truth Establishment**: Methods for establishing ground truth in boundary detection
- **Benchmark Suite Development**: Comprehensive benchmark suites for algorithm evaluation

#### Real-World Validation
- **Case Study Methodologies**: Systematic approaches for real-world validation
- **Longitudinal Studies**: Long-term studies of boundary detection effectiveness
- **Cross-Industry Validation**: Validation across different industry sectors and use cases

---

## Research Summary

This comprehensive research document has examined advanced trust boundary detection algorithms and implementations across multiple dimensions:

1. **Academic Foundations**: Graph theory, spectral analysis, and community detection provide strong mathematical foundations for boundary detection
2. **Practical Implementations**: Current tools show limitations in automated detection, presenting opportunities for advancement
3. **Cloud-Native Patterns**: Modern cloud architectures require sophisticated detection algorithms for VPCs, IAM, and service boundaries
4. **Machine Learning Applications**: ML and AI offer promising approaches for contextual and adaptive boundary detection
5. **Multi-Algorithm Consensus**: Combining multiple approaches provides more robust and reliable boundary detection

**Key Recommendations for Threagile:**
- Implement graph-based analysis as the foundation
- Integrate cloud-specific pattern detection
- Consider ML-based approaches for adaptive detection
- Develop consensus mechanisms for improved reliability
- Focus on interpretability and actionable insights

The research reveals significant opportunities for advancing the state of automated trust boundary detection in threat modeling tools, with practical algorithmic approaches ready for implementation in systems like Threagile.