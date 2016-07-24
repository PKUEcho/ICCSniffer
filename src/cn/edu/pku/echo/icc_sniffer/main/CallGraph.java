package cn.edu.pku.echo.icc_sniffer.main;

import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

import com.googlecode.d2j.Method;
import com.googlecode.d2j.node.DexClassNode;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.node.DexMethodNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.node.insn.MethodStmtNode;
import com.googlecode.d2j.reader.BaseDexFileReader;

public class CallGraph {
	private static void findSucMethods(DexMethodNode dmn, Map<Method, Set<DexMethodNode>> graph) {
		for (DexStmtNode dsn : dmn.codeNode.stmts) {
			if (!(dsn instanceof MethodStmtNode))
				continue;
			MethodStmtNode msn = (MethodStmtNode) dsn;
			if (graph.get(msn.method) == null)
				graph.put(msn.method, new HashSet<DexMethodNode>());
			graph.get(msn.method).add(dmn);
		}
	}

	private static boolean isInterestedMethod(DexMethodNode dmn) {
		for (DexStmtNode dsn : dmn.codeNode.stmts) {
			if (!(dsn instanceof MethodStmtNode))
				continue;
			MethodStmtNode msn = (MethodStmtNode) dsn;
			for (String m : ConstConfig.interested_method) {
				if (m.equals(msn.method.getName()))
					return true;
			}
		}
		return false;
	}

	public static Set<DexMethodNode> findInterestedMethods(BaseDexFileReader dfr, int pro_step) {
		Set<DexMethodNode> ret = new HashSet<DexMethodNode>();
		Map<Method, Set<DexMethodNode>> call_graph = new HashMap<Method, Set<DexMethodNode>>();
		DexFileNode dfn = new DexFileNode();
		dfr.accept(dfn);
		for (DexClassNode dcn : dfn.clzs) {
			if (dcn == null || dcn.methods == null)
				continue;
			for (DexMethodNode dmn : dcn.methods) {
				if (dmn == null || dmn.codeNode == null)
					continue;
				if (isInterestedMethod(dmn)) {
					ret.add(dmn);
				}
				findSucMethods(dmn, call_graph);
			}
		}
		for (int i = 0; i < pro_step; ++i) {
			Set<DexMethodNode> new_ret = new HashSet<DexMethodNode>();
			for (DexMethodNode dmn : ret) {
				new_ret.add(dmn);
				Set<DexMethodNode> preMethods = call_graph.get(dmn.method);
				if (preMethods != null)
					new_ret.addAll(preMethods);
			}
			ret = new_ret;
		}
		return ret;
	}
}
