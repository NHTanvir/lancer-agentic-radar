//! The reconstructed agent graph and the query API detectors run against.

use crate::node::{
    AgentNode, Edge, EdgeKind, MemoryStore, NodeId, NodeKind, RAGSource, ToolEffects, ToolNode,
};
use crate::trust::TrustLabel;
use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// The uniform representation every parser produces and every detector reads.
///
/// The `Vec` collections are the serializable source of truth; a `petgraph`
/// view is built on demand for graph algorithms (cycle detection, reachability).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentGraph {
    pub agents: Vec<AgentNode>,
    pub tools: Vec<ToolNode>,
    pub memory: Vec<MemoryStore>,
    pub rag: Vec<RAGSource>,
    pub edges: Vec<Edge>,
    /// Nodes the parser could not statically resolve (id + display label).
    #[serde(default)]
    pub unknowns: Vec<(NodeId, String)>,
}

impl AgentGraph {
    pub fn new() -> Self {
        Self::default()
    }

    // -- builders -----------------------------------------------------------

    pub fn add_agent(&mut self, a: AgentNode) -> NodeId {
        let id = a.id.clone();
        self.agents.push(a);
        id
    }
    pub fn add_tool(&mut self, t: ToolNode) -> NodeId {
        let id = t.id.clone();
        self.tools.push(t);
        id
    }
    pub fn add_memory(&mut self, m: MemoryStore) -> NodeId {
        let id = m.id.clone();
        self.memory.push(m);
        id
    }
    pub fn add_rag(&mut self, r: RAGSource) -> NodeId {
        let id = r.id.clone();
        self.rag.push(r);
        id
    }
    pub fn add_unknown(&mut self, id: impl Into<NodeId>, label: impl Into<String>) -> NodeId {
        let id = id.into();
        self.unknowns.push((id.clone(), label.into()));
        id
    }
    pub fn add_edge(&mut self, e: Edge) {
        self.edges.push(e);
    }

    /// Merge another graph into this one (used when a scan spans many files).
    pub fn merge(&mut self, other: AgentGraph) {
        self.agents.extend(other.agents);
        self.tools.extend(other.tools);
        self.memory.extend(other.memory);
        self.rag.extend(other.rag);
        self.edges.extend(other.edges);
        self.unknowns.extend(other.unknowns);
        self.dedup();
    }

    /// Remove duplicate nodes/edges by id (upstream v0.14 de-duplicates tool
    /// nodes in graph output; we match that).
    pub fn dedup(&mut self) {
        dedup_by_id(&mut self.agents, |a| a.id.clone());
        dedup_by_id(&mut self.tools, |t| t.id.clone());
        dedup_by_id(&mut self.memory, |m| m.id.clone());
        dedup_by_id(&mut self.rag, |r| r.id.clone());
        let mut seen = HashSet::new();
        self.edges
            .retain(|e| seen.insert((e.from.clone(), e.to.clone(), e.kind)));
        let mut seenu = HashSet::new();
        self.unknowns.retain(|(id, _)| seenu.insert(id.clone()));
    }

    // -- lookups ------------------------------------------------------------

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
            && self.tools.is_empty()
            && self.memory.is_empty()
            && self.rag.is_empty()
    }

    pub fn node_count(&self) -> usize {
        self.agents.len() + self.tools.len() + self.memory.len() + self.rag.len()
            + self.unknowns.len()
    }

    pub fn agent(&self, id: &NodeId) -> Option<&AgentNode> {
        self.agents.iter().find(|a| &a.id == id)
    }
    pub fn tool(&self, id: &NodeId) -> Option<&ToolNode> {
        self.tools.iter().find(|t| &t.id == id)
    }
    pub fn memory_store(&self, id: &NodeId) -> Option<&MemoryStore> {
        self.memory.iter().find(|m| &m.id == id)
    }
    pub fn rag_source(&self, id: &NodeId) -> Option<&RAGSource> {
        self.rag.iter().find(|r| &r.id == id)
    }

    /// Classify a node id into its kind.
    pub fn kind_of(&self, id: &NodeId) -> Option<NodeKind> {
        if self.agent(id).is_some() {
            Some(NodeKind::Agent)
        } else if self.tool(id).is_some() {
            Some(NodeKind::Tool)
        } else if self.memory_store(id).is_some() {
            Some(NodeKind::Memory)
        } else if self.rag_source(id).is_some() {
            Some(NodeKind::Rag)
        } else if self.unknowns.iter().any(|(u, _)| u == id) {
            Some(NodeKind::Unknown)
        } else {
            None
        }
    }

    /// Best-effort display name for any node id.
    pub fn name_of(&self, id: &NodeId) -> String {
        if let Some(a) = self.agent(id) {
            a.name.clone()
        } else if let Some(t) = self.tool(id) {
            t.name.clone()
        } else if let Some(m) = self.memory_store(id) {
            m.name.clone()
        } else if let Some(r) = self.rag_source(id) {
            r.name.clone()
        } else if let Some((_, l)) = self.unknowns.iter().find(|(u, _)| u == id) {
            l.clone()
        } else {
            id.0.clone()
        }
    }

    // -- adjacency ----------------------------------------------------------

    /// Edges leaving `id`.
    pub fn edges_from<'a>(&'a self, id: &'a NodeId) -> impl Iterator<Item = &'a Edge> + 'a {
        self.edges.iter().filter(move |e| &e.from == id)
    }
    /// Edges entering `id`.
    pub fn edges_into<'a>(&'a self, id: &'a NodeId) -> impl Iterator<Item = &'a Edge> + 'a {
        self.edges.iter().filter(move |e| &e.to == id)
    }

    /// Tools an agent is permitted to call.
    pub fn tools_of<'a>(&'a self, agent: &'a NodeId) -> Vec<&'a ToolNode> {
        self.edges_from(agent)
            .filter(|e| e.kind == EdgeKind::Calls)
            .filter_map(|e| self.tool(&e.to))
            .collect()
    }

    /// Agents permitted to call a given tool.
    pub fn agents_calling<'a>(&'a self, tool: &'a NodeId) -> Vec<&'a AgentNode> {
        self.edges_into(tool)
            .filter(|e| e.kind == EdgeKind::Calls)
            .filter_map(|e| self.agent(&e.from))
            .collect()
    }

    /// All (agent, tool) pairs where the tool's effects match `pred`.
    pub fn agents_calling_tool_with_effect<'a>(
        &'a self,
        pred: impl Fn(&ToolEffects) -> bool,
    ) -> Vec<(&'a AgentNode, &'a ToolNode)> {
        let mut out = Vec::new();
        for e in self.edges.iter().filter(|e| e.kind == EdgeKind::Calls) {
            if let (Some(a), Some(t)) = (self.agent(&e.from), self.tool(&e.to)) {
                if pred(&t.effects) {
                    out.push((a, t));
                }
            }
        }
        out
    }

    /// RAG sources read by an agent.
    pub fn rag_of<'a>(&'a self, agent: &'a NodeId) -> Vec<&'a RAGSource> {
        self.edges_from(agent)
            .filter(|e| e.kind == EdgeKind::Reads)
            .filter_map(|e| self.rag_source(&e.to))
            .collect()
    }

    /// Memory stores touched (read or written) by an agent.
    pub fn memory_of<'a>(&'a self, agent: &'a NodeId) -> Vec<&'a MemoryStore> {
        self.edges_from(agent)
            .filter(|e| matches!(e.kind, EdgeKind::Reads | EdgeKind::Writes))
            .filter_map(|e| self.memory_store(&e.to))
            .collect()
    }

    // -- trust propagation --------------------------------------------------

    /// Inherent trust label of a node before propagation.
    fn inherent_trust(&self, id: &NodeId) -> TrustLabel {
        if let Some(a) = self.agent(id) {
            // Raw LLM output is mixed; an agent fed user input is a source of
            // untrust.
            if a.accepts_user_input {
                TrustLabel::Untrusted
            } else {
                TrustLabel::Mixed
            }
        } else if let Some(t) = self.tool(id) {
            // Tools that pull external data are untrusted sources.
            if t.effects.net_egress {
                TrustLabel::Untrusted
            } else {
                TrustLabel::Unknown
            }
        } else if let Some(m) = self.memory_store(id) {
            if m.cross_session {
                TrustLabel::Mixed
            } else {
                TrustLabel::Unknown
            }
        } else if let Some(r) = self.rag_source(id) {
            r.trust
        } else if self.unknowns.iter().any(|(u, _)| u == id) {
            // Conservatively treat unresolved nodes as untrusted.
            TrustLabel::Untrusted
        } else {
            TrustLabel::Unknown
        }
    }

    /// Compute effective trust labels for every node via fixpoint iteration
    /// (graphs may contain cycles, so we iterate to stability).
    pub fn trust_labels(&self) -> HashMap<NodeId, TrustLabel> {
        let mut label: HashMap<NodeId, TrustLabel> = HashMap::new();
        for id in self.all_ids() {
            label.insert(id.clone(), self.inherent_trust(&id));
        }
        // Predecessor adjacency.
        let mut preds: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for e in &self.edges {
            preds.entry(e.to.clone()).or_default().push(e.from.clone());
        }
        let cap = self.node_count() + 2;
        for _ in 0..cap {
            let mut changed = false;
            for (id, ps) in &preds {
                let mut acc = *label.get(id).unwrap_or(&TrustLabel::Unknown);
                for p in ps {
                    acc = acc.join(*label.get(p).unwrap_or(&TrustLabel::Unknown));
                }
                if label.get(id) != Some(&acc) {
                    label.insert(id.clone(), acc);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        label
    }

    /// Run propagation and write the resulting label onto each edge (the edge
    /// carries the trust of the *data leaving its source*).
    pub fn propagate_trust(&mut self) {
        let labels = self.trust_labels();
        for e in &mut self.edges {
            e.trust = *labels.get(&e.from).unwrap_or(&TrustLabel::Unknown);
        }
    }

    /// Edges where tainted data reaches a privileged tool — the core
    /// trust-boundary signal.
    pub fn edges_crossing_trust_boundary(&self) -> Vec<&Edge> {
        let labels = self.trust_labels();
        self.edges
            .iter()
            .filter(|e| {
                let src_tainted = labels
                    .get(&e.from)
                    .map(|l| l.is_tainted())
                    .unwrap_or(false);
                let sink_privileged = self
                    .tool(&e.to)
                    .map(|t| t.effects.is_privileged())
                    .unwrap_or(false);
                src_tainted && sink_privileged && e.kind == EdgeKind::Calls
            })
            .collect()
    }

    // -- petgraph view / cycles --------------------------------------------

    fn all_ids(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = Vec::with_capacity(self.node_count());
        v.extend(self.agents.iter().map(|a| a.id.clone()));
        v.extend(self.tools.iter().map(|t| t.id.clone()));
        v.extend(self.memory.iter().map(|m| m.id.clone()));
        v.extend(self.rag.iter().map(|r| r.id.clone()));
        v.extend(self.unknowns.iter().map(|(u, _)| u.clone()));
        v
    }

    /// Build a `petgraph` view (node weight = NodeId, edge weight = EdgeKind).
    pub fn to_petgraph(&self) -> (DiGraph<NodeId, EdgeKind>, HashMap<NodeId, NodeIndex>) {
        let mut g = DiGraph::<NodeId, EdgeKind>::new();
        let mut idx = HashMap::new();
        for id in self.all_ids() {
            let ni = g.add_node(id.clone());
            idx.insert(id, ni);
        }
        for e in &self.edges {
            if let (Some(&a), Some(&b)) = (idx.get(&e.from), idx.get(&e.to)) {
                g.add_edge(a, b, e.kind);
            }
        }
        (g, idx)
    }

    /// Strongly-connected components with more than one node, or self-loops —
    /// i.e. cycles in the agent/tool graph (recursion-bomb / infinite-loop
    /// signal).
    pub fn cycles(&self) -> Vec<Vec<NodeId>> {
        let (g, _) = self.to_petgraph();
        let mut out = Vec::new();
        for scc in kosaraju_scc(&g) {
            if scc.len() > 1 {
                out.push(scc.into_iter().map(|ni| g[ni].clone()).collect());
            } else if let Some(&ni) = scc.first() {
                // self-loop?
                if g.neighbors(ni).any(|n| n == ni) {
                    out.push(vec![g[ni].clone()]);
                }
            }
        }
        out
    }

    /// Whether `to` is reachable from `from` along directed edges.
    pub fn reachable(&self, from: &NodeId, to: &NodeId) -> bool {
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut q: VecDeque<NodeId> = VecDeque::new();
        q.push_back(from.clone());
        seen.insert(from.clone());
        while let Some(cur) = q.pop_front() {
            if &cur == to {
                return true;
            }
            for e in self.edges_from(&cur) {
                if seen.insert(e.to.clone()) {
                    q.push_back(e.to.clone());
                }
            }
        }
        false
    }

    /// Handoff edges between agents (used by handoff-abuse detectors).
    pub fn handoff_edges(&self) -> Vec<&Edge> {
        self.edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Handoff)
            .collect()
    }
}

fn dedup_by_id<T, F>(v: &mut Vec<T>, key: F)
where
    F: Fn(&T) -> NodeId,
{
    let mut seen = HashSet::new();
    v.retain(|item| seen.insert(key(item)));
}
