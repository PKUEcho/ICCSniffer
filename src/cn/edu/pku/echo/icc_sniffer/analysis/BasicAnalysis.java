package cn.edu.pku.echo.icc_sniffer.analysis;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.googlecode.d2j.node.DexClassNode;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.reader.DexFileReader;

public class BasicAnalysis {
	private String apkName;

	public BasicAnalysis(String name) {
		apkName = name;
	}

	public List<DexClassNode> getClassNode() {
		List<DexClassNode> cnList = new ArrayList<DexClassNode>();
		try {
			List<DexFileReader> list = getDexReaders();
			for (DexFileReader fr : list) {
				DexFileNode dfn = new DexFileNode();
				fr.accept(dfn);
				for (DexClassNode cn : dfn.clzs) {
//					if (ConfLoader.getInstance().inSEAClass(cn.className)) {
						cnList.add(cn);
//					}
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cnList;
	}

	private List<DexFileReader> getDexReaders() throws FileNotFoundException,
			IOException {
		if (apkName.endsWith("dex")) {
			List<DexFileReader> ret = new ArrayList<DexFileReader>();
			ret.add(new DexFileReader(new FileInputStream(apkName)));
			return ret;
		} else
			return getDexReadersFromApk(new ZipInputStream(new FileInputStream(
					apkName)));

	}

	private List<DexFileReader> getDexReadersFromApk(ZipInputStream zin)
			throws IOException {
		ZipEntry next;
		List<DexFileReader> ret = new ArrayList<DexFileReader>();
		for (; (next = zin.getNextEntry()) != null;) {
			String name = next.getName();
			if (name.startsWith("classes") && name.endsWith(".dex")) {
				ret.add(new DexFileReader(zin));
			} else if (name.endsWith(".jar")) {
				ret.addAll(getDexReadersFromApk(new ZipInputStream(zin)));
			}
		}
		return ret;
	}
}
