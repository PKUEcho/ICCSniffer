package cn.edu.pku.echo.icc_sniffer.analysis;

import com.googlecode.d2j.node.insn.ConstStmtNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.node.insn.MethodStmtNode;
import com.googlecode.d2j.node.insn.TypeStmtNode;

public class ConstMethods {
	
	// New instance of String
	// const-string/jumbo v0, "com.tencent.mm.login.ACTION_LOGOUT"
	public static boolean isNewInstanceString(DexStmtNode dsn) {
		if (!(dsn instanceof ConstStmtNode))
			return false;
		ConstStmtNode csn = (ConstStmtNode) dsn;
		return csn.value instanceof String;
	}
	
	// new-instance v1, Landroid/content/Intent;
	public static boolean isNewInstanceIntent(DexStmtNode dsn) {
		if (!(dsn instanceof TypeStmtNode))
			return false;
		TypeStmtNode tsn = (TypeStmtNode) dsn;
		return "Landroid/content/Intent;".equals(tsn.type);
	}
	
	// new-instance v1, Landroid/content/ComponentName;
	public static boolean isNewInstanceComponentName(DexStmtNode dsn) {
		if (!(dsn instanceof TypeStmtNode))
			return false;
		TypeStmtNode tsn = (TypeStmtNode) dsn;
		return "Landroid/content/ComponentName;".equals(tsn.type);
	}
	
	// invoke-direct {v1, v0},
	// Landroid/content/Intent;-><init>(Ljava/lang/String;)V
	public static boolean isInitIntent(DexStmtNode dsn) {
		if (!(dsn instanceof MethodStmtNode))
			return false;
		MethodStmtNode msn = (MethodStmtNode) dsn;
		return (msn.method.getOwner().equals("Landroid/content/Intent;")) && (msn.method.getName().equals("<init>"));
	}

	// invoke-direct {v1, v3, v4},
	// Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V
	public static boolean isInitComponentName(DexStmtNode dsn) {
		if (!(dsn instanceof MethodStmtNode))
			return false;
		MethodStmtNode msn = (MethodStmtNode) dsn;
		return (msn.method.getOwner().equals("Landroid/content/ComponentName;"))
				&& (msn.method.getName().equals("<init>"));
	}

	// invoke-virtual {v4, v5},
	// Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;
	public static boolean isSetAction(DexStmtNode dsn) {
		if (!(dsn instanceof MethodStmtNode))
			return false;
		MethodStmtNode msn = (MethodStmtNode) dsn;
		return (msn.method.getOwner().equals("Landroid/content/Intent;")) && (msn.method.getName().equals("setAction"));
	}

	// invoke-virtual {v0, v1},
	// Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;
	public static boolean isSetComponent(DexStmtNode dsn) {
		if (!(dsn instanceof MethodStmtNode))
			return false;
		MethodStmtNode msn = (MethodStmtNode) dsn;
		return (msn.method.getOwner().equals("Landroid/content/Intent;"))
				&& (msn.method.getName().equals("setComponent"));
	}
	
	// invoke-virtual {v0, p1, v1},
	// Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
	public static boolean isSetClassName(DexStmtNode dsn) {
		if (!(dsn instanceof MethodStmtNode))
			return false;
		MethodStmtNode msn = (MethodStmtNode) dsn;
		return (msn.method.getOwner().equals("Landroid/content/Intent;"))
				&& (msn.method.getName().equals("setClassName"));
	}
	
	public static boolean isSetPackage(DexStmtNode dsn) {
		if (!(dsn instanceof MethodStmtNode))
			return false;
		MethodStmtNode msn = (MethodStmtNode) dsn;
		return (msn.method.getOwner().equals("Landroid/content/Intent;"))
				&& (msn.method.getName().equals("setPackage"));
	}
	
	public static boolean isAddCategory(DexStmtNode dsn) {
		if (!(dsn instanceof MethodStmtNode))
			return false;
		MethodStmtNode msn = (MethodStmtNode) dsn;
		return (msn.method.getOwner().equals("Landroid/content/Intent;"))
				&& (msn.method.getName().equals("addCategory"));
	}
}
