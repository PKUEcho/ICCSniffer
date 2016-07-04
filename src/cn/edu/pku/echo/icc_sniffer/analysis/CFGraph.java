package cn.edu.pku.echo.icc_sniffer.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.googlecode.d2j.DexConstants;
import com.googlecode.d2j.DexLabel;
import com.googlecode.d2j.Method;
import com.googlecode.d2j.node.DexMethodNode;
import com.googlecode.d2j.node.TryCatchNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.node.insn.JumpStmtNode;
import com.googlecode.d2j.node.insn.DexLabelStmtNode;

public abstract class CFGraph implements DexConstants {
	protected List<BasicBlock> basicBlocks;
	private Map<BasicBlock, Set<BasicBlock>> preBlock;
	protected Map<BasicBlock, Set<BasicBlock>> sucBlock;
	private Map<DexLabel, BasicBlock> labelToBB;

	public Method currentMethod;
	public int totalRegister;
	private int methodAccess;
	private BasicBlock lastBlock;
	public List<TryCatchNode> tryCatch;

	public CFGraph(DexMethodNode dmn) {
		currentMethod = dmn.method;
		methodAccess = dmn.access;
		totalRegister = dmn.codeNode.totalRegister;
		buildBasicBlock(dmn.codeNode.stmts, dmn.codeNode.tryStmts);
	}

	public boolean isStatic() {
		return (methodAccess & ACC_STATIC) != 0;
	}

	public abstract BasicBlock getNewBasicBlock(int id);

	// {
	// return new BasicBlock(id);
	// };

	public List<BasicBlock> getBasicBlocks() {
		return basicBlocks;
	}

	public BasicBlock firstBlock() {
		return basicBlocks.get(0);
	}

	public BasicBlock lastBlock() {
		return lastBlock;
	}

	public Set<BasicBlock> getSucBlocks(BasicBlock b) {
		if (!sucBlock.containsKey(b)) {
			Set<BasicBlock> ret = new HashSet<BasicBlock>();
			sucBlock.put(b, ret);
			return ret;
		}
		return sucBlock.get(b);
	}

	public Set<BasicBlock> getPreBlocks(BasicBlock b) {
		if (!preBlock.containsKey(b)) {
			Set<BasicBlock> ret = new HashSet<BasicBlock>();
			preBlock.put(b, ret);
			return ret;
		}
		return preBlock.get(b);
	}

	public void buildBasicBlock(List<DexStmtNode> stmts,
			List<TryCatchNode> tryStmts) {
		basicBlocks = new ArrayList<BasicBlock>();
		preBlock = new HashMap<BasicBlock, Set<BasicBlock>>();
		sucBlock = new HashMap<BasicBlock, Set<BasicBlock>>();
		labelToBB = new HashMap<DexLabel, BasicBlock>();
		tryCatch = tryStmts;
		BasicBlock current = null;
		int id = 0;
		// Should we add a beginning bb?
		// basicBlocks.add(new BasicBlock(id++));
		for (DexStmtNode dsn : stmts) {
			if (current == null || isBasicBlockStart(dsn)) {
				current = getNewBasicBlock(id++);
				basicBlocks.add(current);
			}
			if (isBasicBlockEnd(dsn)) {
				current.addInsn(dsn);
				current.markSucLabel();
				current = null;
			} else {
				current.addInsn(dsn);
				if (dsn instanceof DexLabelStmtNode) {
					DexLabelStmtNode ln = (DexLabelStmtNode) dsn;
					labelToBB.put(ln.label, current);
				}
			}
		}
		// We should add a last bb for return/throw stmts.
		current = getNewBasicBlock(id++);
		// current.addInsn(new DexLabelStmtNode(new DexLable(-1)));
		basicBlocks.add(current);
		buildPreSuc();
	}

	private boolean isBasicBlockStart(DexStmtNode dsn) {
		return (dsn instanceof DexLabelStmtNode);
	}

	private void buildPreSuc() {
		BasicBlock current;
		lastBlock = basicBlocks.get(basicBlocks.size() - 1);
		int nextTryCatch = 0;
		TryCatchNode currentTryCatch = null;
		for (int i = 0; i < basicBlocks.size(); i++) {
			current = basicBlocks.get(i);
			if (current.insn.size() > 0
					&& isBasicBlockStart(current.insn.get(0))) {
				DexLabelStmtNode label = (DexLabelStmtNode) current.insn.get(0);
				TryCatchNode nextTCNode = null;
				if (tryCatch != null && tryCatch.size() > nextTryCatch)
					nextTCNode = tryCatch.get(nextTryCatch);
				if (nextTCNode != null && nextTCNode.start == label.label) {
					currentTryCatch = nextTCNode;
					nextTryCatch++;
				}
				if (currentTryCatch != null
						&& currentTryCatch.end == label.label) {
					currentTryCatch = null;
				}
			}

			if (current.canContinue())
				addPreAndSuc(current, basicBlocks.get(i + 1));
			if (current.canThrow()) {
				// TODO consider the try catch types.
				addPreAndSuc(current, lastBlock);
				if (currentTryCatch != null)
					for (DexLabel l : currentTryCatch.handler)
						addPreAndSuc(current, getBBByLable(l));
			}
			if (current.canReturn())
				addPreAndSuc(current, lastBlock);
			if (current.canBranch() || current.canSwitch()) {
				Set<DexLabel> ls = current.getSucLabels();
				for (DexLabel l : ls) {
					BasicBlock next = getBBByLable(l);
					addPreAndSuc(current, next);
				}
			}
		}
	}

	private BasicBlock getBBByLable(DexLabel l) {
		return labelToBB.get(l);
	}

	private void addPreAndSuc(BasicBlock pre, BasicBlock suc) {
		Set<BasicBlock> s = getNotNullSet(pre, sucBlock);
		s.add(suc);
		s = getNotNullSet(suc, preBlock);
		s.add(pre);

	}

	protected Set<BasicBlock> getNotNullSet(BasicBlock pre,
			Map<BasicBlock, Set<BasicBlock>> map) {
		Set<BasicBlock> ret;
		if (map.containsKey(pre))
			return map.get(pre);
		else {
			ret = new HashSet<BasicBlock>();
			map.put(pre, ret);
			return ret;
		}
	}

	private boolean isBasicBlockEnd(DexStmtNode dsn) {
		// TODO
		if (dsn instanceof JumpStmtNode)
			return true;
		if (dsn.op != null)
			return dsn.op.canBranch() || dsn.op.canReturn()
					|| dsn.op.canSwitch() || dsn.op.canThrow();
		return false;
	}

	public void printCFG() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < basicBlocks.size(); i++) {
			BasicBlock current = basicBlocks.get(i);
			sb.append("B").append(current.getId()).append(" --> ");
			Set<BasicBlock> nexts = getNotNullSet(current, sucBlock);
			for (BasicBlock next : nexts)
				sb.append("B").append(next.getId()).append(" ");
			sb.append("\n");
		}
		sb.append("============Insn========");
		System.out.println(sb);
		System.out.println("==========Finished ========");
	}
}
