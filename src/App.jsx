import React, { useState, useEffect } from 'react';
import { 
  Lock, Unlock, Shield, Key, Plus, Copy, Eye, EyeOff, 
  Trash2, Search, Check, AlertTriangle, RefreshCw, X, Save,
  Cloud, LogOut, User, Loader2, Fingerprint, Download, Upload, AlertOctagon, Mail,
  FileText, ListFilter, ChevronRight, ChevronDown, ImageIcon, Globe
} from 'lucide-react';

// --- FIREBASE SETUP ---
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithPopup, GoogleAuthProvider, onAuthStateChanged, signOut } from 'firebase/auth';
import { getFirestore, doc, setDoc, onSnapshot, deleteDoc } from 'firebase/firestore';

// Cấu hình Firebase
const firebaseConfig = {
  apiKey: "AIzaSyCa-bC8UrfSX_Ir0_2vXTAlBS10Hzr7RDI",
  authDomain: "quanlymatkhau.firebaseapp.com",
  projectId: "quanlymatkhau",
  storageBucket: "quanlymatkhau.firebasestorage.app",
  messagingSenderId: "144750647329",
  appId: "1:144750647329:web:fd6dbe1ca10b652f21eb60"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

const getVaultDocRef = (userId) => {
  return doc(db, 'users', userId, 'secure_vault', 'encrypted_blob');
};

const buf2b64 = (buf) => btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
const b642buf = (b64) => {
  const binary_string = atob(b64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};

const ITERATIONS = 100000;

const getPasswordKey = (password) => {
  return window.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
};

const deriveKey = async (passwordKey, salt) => {
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: ITERATIONS, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
};

const encryptData = async (data, key) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedData = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encodedData
  );
  return { ciphertext, iv };
};

const decryptData = async (ciphertext, iv, key) => {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
};

// Hàm tiện ích lấy Favicon từ URL
const getFaviconUrl = (url) => {
  if (!url) return null;
  try {
    const domain = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
    return `https://s2.googleusercontent.com/s2/favicons?domain=${domain}&sz=64`;
  } catch {
    return null;
  }
};

// --- COMPONENT CHÍNH ---
export default function App() {
  const [user, setUser] = useState(null);
  const [appState, setAppState] = useState('CHECKING_AUTH'); 
  
  const [masterKey, setMasterKey] = useState(null);
  const [vaultSalt, setVaultSalt] = useState(null);
  const [vault, setVault] = useState([]);
  const [encryptedCloudData, setEncryptedCloudData] = useState(null);
  
  const [masterPasswordInput, setMasterPasswordInput] = useState('');
  const [confirmPasswordInput, setConfirmPasswordInput] = useState('');
  const [passwordHintInput, setPasswordHintInput] = useState(''); 
  const [authError, setAuthError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all'); 
  
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingItem, setEditingItem] = useState(null);
  const [toastMessage, setToastMessage] = useState(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const [showHint, setShowHint] = useState(false);

  const [isBiometricSupported, setIsBiometricSupported] = useState(false);
  const [hasBiometricSaved, setHasBiometricSaved] = useState(!!localStorage.getItem('sv_biometric_pwd'));

  useEffect(() => {
    if (window.PublicKeyCredential) {
      window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then(available => setIsBiometricSupported(available));
    }
  }, []);

  const enableBiometric = async () => {
    try {
      const challenge = window.crypto.getRandomValues(new Uint8Array(32));
      const userId = window.crypto.getRandomValues(new Uint8Array(16));
      const publicKey = {
        challenge: challenge,
        rp: { name: "SecureVault", id: window.location.hostname },
        user: { id: userId, name: user.email, displayName: user.email },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
        timeout: 60000,
      };
      
      await navigator.credentials.create({ publicKey });
      localStorage.setItem('sv_biometric_pwd', masterPasswordInput);
      setHasBiometricSaved(true);
      showToast("Đã thiết lập Face ID/Vân tay thành công!");
    } catch (err) {
      showToast("Hủy thao tác hoặc thiết bị không hỗ trợ.");
    }
  };

  const handleBiometricUnlock = async () => {
    try {
      setAuthError('');
      const challenge = window.crypto.getRandomValues(new Uint8Array(32));
      const publicKey = {
        challenge: challenge,
        rpId: window.location.hostname,
        userVerification: "required",
      };
      
      await navigator.credentials.get({ publicKey });
      const savedPwd = localStorage.getItem('sv_biometric_pwd');
      if (savedPwd) {
        await processUnlock(savedPwd);
      } else {
        setAuthError("Không tìm thấy dữ liệu sinh trắc học. Vui lòng nhập mật khẩu.");
      }
    } catch (err) {
      setAuthError("Xác thực khuôn mặt/vân tay thất bại.");
    }
  };

  const processUnlock = async (password) => {
    if (!encryptedCloudData) throw new Error("No data");
    const salt = b642buf(encryptedCloudData.salt);
    const iv = b642buf(encryptedCloudData.iv);
    const ciphertext = b642buf(encryptedCloudData.data);
    
    const pwdKey = await getPasswordKey(password);
    const key = await deriveKey(pwdKey, salt);
    
    const decryptedVault = await decryptData(ciphertext, iv, key);
    
    setVaultSalt(salt);
    setMasterKey(key);
    setVault(decryptedVault);
    setAppState('READY');
    setMasterPasswordInput(password);
    showToast("Đã mở khóa!");
  };

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      if (currentUser) {
        setUser(currentUser);
        setAppState('CHECKING_DATA');
      } else {
        setUser(null);
        setAppState('LOGIN');
      }
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    if (!user || appState === 'LOGIN' || appState === 'CHECKING_AUTH') return;

    const docRef = getVaultDocRef(user.uid);
    const unsubscribe = onSnapshot(docRef, (docSnap) => {
      if (docSnap.exists()) {
        const data = docSnap.data();
        setEncryptedCloudData(data);
        setAppState(prev => (prev === 'CHECKING_DATA' || prev === 'READY' ? 'UNLOCK' : prev));
      } else {
        setAppState('SETUP');
      }
    }, (error) => {
      showToast("Lỗi kết nối máy chủ dữ liệu! Hãy kiểm tra lại cấu hình Firebase.");
    });

    return () => unsubscribe();
  }, [user]);

  const showToast = (message) => {
    setToastMessage(message);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const copyToClipboard = (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => {
        showToast("Đã sao chép!");
      }).catch(err => showToast("Lỗi sao chép!"));
    } else {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
        showToast("Đã sao chép!");
      } catch (err) {
        showToast("Lỗi sao chép!");
      }
      document.body.removeChild(textArea);
    }
  };

  const handleGoogleLogin = async () => {
    setAuthError('');
    const provider = new GoogleAuthProvider();
    try {
      await signInWithPopup(auth, provider);
    } catch (error) {
      if (error.code === 'auth/unauthorized-domain') {
        setAuthError("Tên miền này chưa được cấp phép. Vui lòng thêm tên miền hiện tại vào mục Authorized domains trong Firebase Console.");
      } else {
        setAuthError("Lỗi đăng nhập: " + error.message);
      }
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      setMasterKey(null);
      setVaultSalt(null);
      setVault([]);
      setEncryptedCloudData(null);
      setMasterPasswordInput('');
      setAppState('LOGIN');
      showToast("Đã đăng xuất");
    } catch (error) {
      showToast("Lỗi đăng xuất!");
    }
  };

  const handleLock = () => {
    setMasterKey(null);
    setVaultSalt(null);
    setVault([]);
    setAppState('UNLOCK');
    setMasterPasswordInput('');
    setShowHint(false);
    showToast("Đã khóa kho an toàn.");
  };

  const handleResetVault = async () => {
    if (!user) return;
    const confirmMessage = "CẢNH BÁO ĐỎ:\n\nBạn đang yêu cầu XÓA VĨNH VIỄN toàn bộ mật khẩu trên đám mây để thiết lập lại từ đầu do quên Mật khẩu chính.\n\nHành động này KHÔNG THỂ HOÀN TÁC.\nBạn có chắc chắn muốn tiếp tục?";
    
    if (window.confirm(confirmMessage)) {
      const typeConfirm = window.prompt("Gõ chữ 'XOA' (viết hoa, không dấu) để xác nhận xóa toàn bộ dữ liệu:");
      if (typeConfirm === 'XOA') {
        setIsSyncing(true);
        try {
          const docRef = getVaultDocRef(user.uid);
          await deleteDoc(docRef);
          setEncryptedCloudData(null);
          setAppState('SETUP');
          showToast("Đã xóa kho dữ liệu cũ. Hãy tạo Mật khẩu chính mới.");
        } catch (error) {
          showToast("Lỗi khi xóa dữ liệu trên đám mây.");
        } finally {
          setIsSyncing(false);
        }
      } else if (typeConfirm !== null) {
        showToast("Xác nhận không đúng. Đã hủy thao tác xóa.");
      }
    }
  };

  const exportBackup = () => {
    if (!encryptedCloudData) return showToast("Không có dữ liệu để sao lưu!");
    const dataStr = JSON.stringify(encryptedCloudData);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `SecureVault_Backup_${new Date().toISOString().split('T')[0]}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
    showToast("Đã tải xuống file sao lưu an toàn!");
  };

  const shareBackup = async () => {
    if (!encryptedCloudData) return showToast("Không có dữ liệu để gửi!");
    const dataStr = JSON.stringify(encryptedCloudData);
    const fileName = `SecureVault_Backup_${new Date().toISOString().split('T')[0]}.json`;

    if (navigator.canShare) {
      try {
        const file = new File([dataStr], fileName, { type: 'application/json' });
        if (navigator.canShare({ files: [file] })) {
          await navigator.share({
            files: [file], title: 'Bản sao lưu SecureVault',
            text: 'Đây là bản sao lưu mã hóa kho mật khẩu SecureVault của bạn. Hãy lưu giữ cẩn thận!',
          });
          return;
        }
      } catch (err) {
        if (err.name === 'AbortError') return;
      }
    }

    if (dataStr.length < 1500) {
      const subject = encodeURIComponent("Bản sao lưu SecureVault");
      const body = encodeURIComponent(`Đây là bản sao lưu mã hóa của bạn.\nNếu thiết bị không hỗ trợ file đính kèm, hãy lưu nội dung dưới đây thành file .json để phục hồi khi cần:\n\n${dataStr}`);
      window.location.href = `mailto:${user?.email || ''}?subject=${subject}&body=${body}`;
      showToast("Đã mở ứng dụng Email!");
    } else {
      showToast("Dữ liệu quá lớn để gửi trực tiếp. Vui lòng bấm 'Tải xuống' rồi tự đính kèm vào email!");
    }
  };

  const handleImportBackup = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const content = e.target.result;
        const parsedData = JSON.parse(content);
        if (!parsedData.salt || !parsedData.iv || !parsedData.data) throw new Error("File không hợp lệ");

        if (!window.confirm("CẢNH BÁO: Phục hồi sẽ GHI ĐÈ toàn bộ mật khẩu hiện tại trên đám mây. Bạn có chắc chắn?")) {
          event.target.value = null; return;
        }

        setIsSyncing(true);
        const docRef = getVaultDocRef(user.uid);
        await setDoc(docRef, parsedData);
        showToast("Phục hồi thành công! Vui lòng mở khóa lại.");
        handleLock();
      } catch (err) {
        showToast("Lỗi: File sao lưu không hợp lệ hoặc bị hỏng.");
      } finally {
        setIsSyncing(false);
        event.target.value = null; 
      }
    };
    reader.readAsText(file);
  };

  const saveVaultToCloud = async (newVault, currentKey, currentSalt, setupHint = null) => {
    if (!user) return;
    setIsSyncing(true);
    try {
      const activeKey = currentKey || masterKey;
      const activeSalt = currentSalt || vaultSalt;

      const { ciphertext, iv } = await encryptData(newVault, activeKey);
      const hint = setupHint !== null ? setupHint : (encryptedCloudData?.hint || '');

      const storeData = {
        salt: buf2b64(activeSalt), iv: buf2b64(iv), data: buf2b64(ciphertext),
        hint: hint, updatedAt: new Date().toISOString()
      };

      const docRef = getVaultDocRef(user.uid);
      await setDoc(docRef, storeData);
      setVault(newVault);
    } catch (err) {
      showToast("Lỗi đồng bộ!");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleSetup = async (e) => {
    e.preventDefault();
    if (masterPasswordInput !== confirmPasswordInput) return setAuthError("Mật khẩu xác nhận không khớp!");
    if (masterPasswordInput.length < 8) return setAuthError("Mật khẩu phải có ít nhất 8 ký tự!");

    try {
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const pwdKey = await getPasswordKey(masterPasswordInput);
      const key = await deriveKey(pwdKey, salt);
      
      setVaultSalt(salt); setMasterKey(key);
      await saveVaultToCloud([], key, salt, passwordHintInput);
      
      setAppState('READY'); setMasterPasswordInput(''); setConfirmPasswordInput('');
      setPasswordHintInput(''); setAuthError('');
      showToast("Khởi tạo thành công!");
    } catch (err) {
      setAuthError("Lỗi thiết lập mã hóa.");
    }
  };

  const handleUnlock = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      await processUnlock(masterPasswordInput);
    } catch (err) {
      setAuthError("Sai mật khẩu chính!");
    }
  };

  const handleSaveItem = async (item) => {
    let newVault;
    if (editingItem) {
      newVault = vault.map(v => v.id === item.id ? item : v);
    } else {
      newVault = [{ ...item, id: crypto.randomUUID() }, ...vault];
    }
    await saveVaultToCloud(newVault);
    setShowAddModal(false); setEditingItem(null);
    showToast("Đã lưu & đồng bộ!");
  };

  const handleDeleteItem = async (id) => {
    const newVault = vault.filter(v => v.id !== id);
    await saveVaultToCloud(newVault);
    showToast("Đã xóa!");
  };

  // --- LOGIC NHÓM 1PASSWORD (ALPHABETICAL) ---
  const filteredVault = vault.filter(item => {
    const itemType = item.type || 'password'; 
    const matchesSearch = item.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          (item.username && item.username.toLowerCase().includes(searchQuery.toLowerCase())) ||
                          (itemType === 'note' && item.content && item.content.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = filterType === 'all' || itemType === filterType;
    return matchesSearch && matchesType;
  });

  const sortedVault = [...filteredVault].sort((a, b) => a.title.localeCompare(b.title));
  const groupedVault = sortedVault.reduce((acc, item) => {
    const firstChar = (item.title.charAt(0) || '?').toUpperCase();
    const groupLetter = /[A-Z]/.test(firstChar) ? firstChar : '#';
    if (!acc[groupLetter]) acc[groupLetter] = [];
    acc[groupLetter].push(item);
    return acc;
  }, {});

  // --- RENDER SCREENS ---
  if (appState === 'CHECKING_AUTH' || appState === 'CHECKING_DATA') {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4 text-slate-100">
        <Loader2 className="w-12 h-12 text-blue-500 animate-spin mb-4" />
        <p className="text-slate-400 font-medium">Đang tải dữ liệu an toàn...</p>
      </div>
    );
  }

  if (appState === 'LOGIN') {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 font-sans text-slate-100">
        <div className="bg-slate-900 p-8 rounded-3xl shadow-2xl max-w-md w-full border border-slate-800 text-center">
          <div className="flex justify-center mb-6">
            <div className="bg-blue-500/20 p-4 rounded-2xl">
              <Shield className="w-12 h-12 text-blue-400" />
            </div>
          </div>
          <h1 className="text-2xl font-bold mb-2">SecureVault</h1>
          <p className="text-slate-400 mb-8 text-sm">
            Quản lý mật khẩu an toàn. Đồng bộ đám mây với chuẩn mã hóa quân đội.
          </p>
          {authError && (
            <div className="bg-red-500/10 border border-red-500/50 p-3 rounded-xl mb-6 flex items-start text-left">
              <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5 mr-3 flex-shrink-0" />
              <p className="text-red-400 text-sm">{authError}</p>
            </div>
          )}
          <button onClick={handleGoogleLogin} className="w-full bg-white text-slate-900 hover:bg-slate-100 font-bold py-3.5 px-4 rounded-xl transition-colors flex items-center justify-center shadow-lg">
            <img src="https://www.svgrepo.com/show/475656/google-color.svg" className="w-6 h-6 mr-3" alt="Google" />
            Đăng nhập với Google
          </button>
        </div>
      </div>
    );
  }

  if (appState === 'SETUP') {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 font-sans text-slate-100">
        <div className="bg-slate-900 p-8 rounded-3xl shadow-2xl max-w-md w-full border border-slate-800">
          <div className="flex items-center justify-between mb-6">
            <div className="bg-blue-500/20 p-3 rounded-xl inline-block">
              <Shield className="w-8 h-8 text-blue-400" />
            </div>
            <div className="flex items-center space-x-2 text-sm text-slate-400 bg-slate-950 py-1.5 px-3 rounded-lg border border-slate-800">
              <User className="w-4 h-4 text-blue-400" /> 
              <span className="truncate max-w-[120px]">{user?.email}</span>
            </div>
          </div>
          <h1 className="text-xl font-bold mb-2">Tạo Mật Khẩu Chính</h1>
          <p className="text-slate-400 mb-6 text-sm">Hãy tạo <strong>Mật khẩu chính</strong> để mã hóa kho lưu trữ.</p>
          <div className="bg-amber-900/20 border border-amber-700/30 p-4 rounded-xl mb-6 flex items-start">
            <AlertTriangle className="w-5 h-5 text-amber-500 mt-0.5 mr-3 flex-shrink-0" />
            <p className="text-amber-200/80 text-xs leading-relaxed">
              <strong>Quan trọng:</strong> Tuyệt đối không được quên mật khẩu này. Hệ thống không thể khôi phục nó giúp bạn.
            </p>
          </div>

          <form onSubmit={handleSetup} className="space-y-4">
            <input type="password" value={masterPasswordInput} onChange={(e) => setMasterPasswordInput(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3.5 text-white focus:outline-none focus:border-blue-500 transition-colors" placeholder="Mật khẩu chính (ít nhất 8 ký tự)" required />
            <input type="password" value={confirmPasswordInput} onChange={(e) => setConfirmPasswordInput(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3.5 text-white focus:outline-none focus:border-blue-500 transition-colors" placeholder="Nhập lại mật khẩu" required />
            <input type="text" value={passwordHintInput} onChange={(e) => setPasswordHintInput(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3.5 text-white focus:outline-none focus:border-blue-500 transition-colors" placeholder="Gợi ý mật khẩu (Tùy chọn)" />
            <p className="text-xs text-slate-500 -mt-2 ml-1">Tuyệt đối không nhập nguyên mật khẩu vào ô gợi ý.</p>
            {authError && <p className="text-red-400 text-sm text-center">{authError}</p>}
            <button type="submit" disabled={isSyncing} className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3.5 px-4 rounded-xl flex items-center justify-center transition-colors">
              {isSyncing ? <Loader2 className="w-5 h-5 animate-spin mr-2" /> : <Lock className="w-5 h-5 mr-2" />} Bắt đầu mã hóa
            </button>
            <button type="button" onClick={handleLogout} className="w-full bg-transparent text-slate-500 hover:text-white py-2 text-sm mt-2 transition-colors">Đăng xuất</button>
          </form>
        </div>
      </div>
    );
  }

  if (appState === 'UNLOCK') {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 font-sans text-slate-100">
        <div className="bg-slate-900 p-8 rounded-3xl shadow-2xl max-w-md w-full border border-slate-800">
          <div className="flex items-center justify-between mb-6">
            <div className="bg-emerald-500/20 p-3 rounded-xl inline-block">
              <Lock className="w-8 h-8 text-emerald-400" />
            </div>
            <div className="flex items-center space-x-2 text-sm text-slate-400 bg-slate-950 py-1.5 px-3 rounded-lg border border-slate-800">
              <Cloud className="w-4 h-4 text-emerald-400" /> 
              <span className="truncate max-w-[100px]">{user?.email}</span>
            </div>
          </div>
          <h1 className="text-xl font-bold mb-2">Mở khóa Kho bảo mật</h1>
          <p className="text-slate-400 mb-8 text-sm">Nhập mật khẩu chính để giải mã dữ liệu của bạn.</p>

          <form onSubmit={handleUnlock} className="space-y-5">
            <input type="password" value={masterPasswordInput} onChange={(e) => setMasterPasswordInput(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3.5 text-white focus:outline-none focus:border-emerald-500 transition-colors" placeholder="Mật khẩu chính" required autoFocus />
            {authError && <p className="text-red-400 text-sm text-center">{authError}</p>}
            {showHint && (
              <div className="bg-blue-500/10 border border-blue-500/20 p-4 rounded-xl mb-4 text-left">
                <p className="text-blue-400 text-sm font-medium flex items-center">💡 Gợi ý mật khẩu của bạn:</p>
                <p className="text-slate-300 text-sm mt-2 ml-5">{encryptedCloudData?.hint || "Bạn chưa cài đặt gợi ý cho mật khẩu này."}</p>
              </div>
            )}
            <div className="space-y-3">
              <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3.5 px-4 rounded-xl flex items-center justify-center transition-colors">
                <Unlock className="w-4 h-4 mr-2" /> Giải mã
              </button>
              {isBiometricSupported && hasBiometricSaved && (
                <button type="button" onClick={handleBiometricUnlock} className="w-full bg-slate-800 hover:bg-slate-700 text-emerald-400 font-medium py-3.5 px-4 rounded-xl flex items-center justify-center border border-emerald-500/20 transition-colors">
                  <Fingerprint className="w-5 h-5 mr-2" /> Mở khóa Sinh trắc học
                </button>
              )}
              <button type="button" onClick={handleLogout} className="w-full bg-transparent hover:bg-slate-800 text-slate-500 font-medium py-3.5 px-4 rounded-xl flex items-center justify-center transition-colors">
                <LogOut className="w-4 h-4 mr-2" /> Đăng xuất
              </button>
            </div>
          </form>
          <div className="mt-8 pt-6 border-t border-slate-800 text-center flex flex-col space-y-4">
            {!showHint ? (
              <button type="button" onClick={() => setShowHint(true)} className="text-sm text-slate-500 hover:text-slate-300 transition-colors inline-flex items-center justify-center">Bạn quên mật khẩu chính?</button>
            ) : (
              <button type="button" onClick={handleResetVault} className="text-sm text-slate-500 hover:text-red-400 transition-colors inline-flex items-center justify-center">
                <AlertOctagon className="w-4 h-4 mr-1.5" /> Vẫn không nhớ? Xóa toàn bộ kho
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 font-sans text-slate-200 flex flex-col">
      <nav className="bg-slate-900 border-b border-slate-800 sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="bg-blue-600/20 p-1.5 rounded-lg">
                <Shield className="w-6 h-6 text-blue-500" />
              </div>
              <span className="font-bold text-lg text-white hidden sm:block tracking-wide">SecureVault</span>
            </div>
            
            <div className="flex items-center space-x-2">
              {isSyncing && <RefreshCw className="w-4 h-4 text-blue-400 animate-spin mr-2" />}
              <div className="relative hidden md:block mr-2">
                <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
                <input type="text" placeholder="Search" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:border-blue-500 w-48 lg:w-64 transition-colors" />
              </div>
              {isBiometricSupported && !hasBiometricSaved && (
                <button onClick={enableBiometric} title="Bật Face ID / Vân tay" className="hidden md:flex p-2 text-emerald-400 hover:bg-slate-800 rounded-lg items-center text-sm font-medium border border-emerald-500/20 mr-1"><Fingerprint className="w-5 h-5" /></button>
              )}
              <button onClick={shareBackup} title="Gửi Backup qua Email" className="p-2 text-purple-400 hover:bg-slate-800 rounded-lg hidden sm:block"><Mail className="w-5 h-5" /></button>
              <button onClick={exportBackup} title="Tải file Sao lưu" className="p-2 text-blue-400 hover:bg-slate-800 rounded-lg hidden sm:block"><Download className="w-5 h-5" /></button>
              <button onClick={() => document.getElementById('backup-upload').click()} title="Phục hồi từ file" className="p-2 text-amber-400 hover:bg-slate-800 rounded-lg hidden sm:block"><Upload className="w-5 h-5" /></button>
              <input type="file" id="backup-upload" accept=".json" style={{ display: 'none' }} onChange={handleImportBackup} />
              <button onClick={handleLock} className="p-2 text-slate-400 hover:bg-slate-800 rounded-lg"><Lock className="w-5 h-5" /></button>
              <button onClick={handleLogout} className="p-2 text-rose-400 hover:bg-rose-500/10 rounded-lg"><LogOut className="w-5 h-5" /></button>
            </div>
          </div>
        </div>
      </nav>

      <main className="flex-1 max-w-4xl mx-auto px-4 py-8 w-full mb-20 md:mb-6">
        <div className="flex justify-between items-end md:items-center mb-6">
          <div className="flex flex-col md:flex-row md:items-center gap-4 w-full">
            <h2 className="text-2xl font-bold text-white whitespace-nowrap">Tất cả mục</h2>
            <div className="flex space-x-2 overflow-x-auto pb-1 md:pb-0 scrollbar-hide w-full md:w-auto">
              <button onClick={() => setFilterType('all')} className={`px-4 py-1.5 rounded-full text-sm font-medium whitespace-nowrap transition-colors ${filterType === 'all' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700 border border-slate-700/50'}`}>Tất cả</button>
              <button onClick={() => setFilterType('password')} className={`px-4 py-1.5 rounded-full text-sm font-medium whitespace-nowrap transition-colors ${filterType === 'password' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700 border border-slate-700/50'}`}>Đăng nhập</button>
              <button onClick={() => setFilterType('note')} className={`px-4 py-1.5 rounded-full text-sm font-medium whitespace-nowrap transition-colors ${filterType === 'note' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700 border border-slate-700/50'}`}>Ghi chú</button>
            </div>
          </div>
          
          <div className="flex space-x-2 flex-shrink-0 mb-1 md:mb-0">
            <button onClick={shareBackup} className="md:hidden flex bg-slate-800 text-purple-400 border border-purple-500/20 px-3 py-2 rounded-lg font-medium items-center"><Mail className="w-5 h-5" /></button>
            <button onClick={exportBackup} className="md:hidden flex bg-slate-800 text-blue-400 border border-blue-500/20 px-3 py-2 rounded-lg font-medium items-center"><Download className="w-5 h-5" /></button>
            <button onClick={() => document.getElementById('backup-upload').click()} className="md:hidden flex bg-slate-800 text-amber-400 border border-amber-500/20 px-3 py-2 rounded-lg font-medium items-center"><Upload className="w-5 h-5" /></button>
            {isBiometricSupported && !hasBiometricSaved && (
              <button onClick={enableBiometric} className="md:hidden flex bg-slate-800 text-emerald-400 border border-emerald-500/20 px-3 py-2 rounded-lg font-medium items-center"><Fingerprint className="w-5 h-5" /></button>
            )}
            <button onClick={() => { setEditingItem(null); setShowAddModal(true); }} className="hidden md:flex bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg font-medium items-center shadow-lg shadow-blue-600/20 transition-colors">
              <Plus className="w-5 h-5 mr-1" /> Thêm mới
            </button>
          </div>
        </div>

        <div className="relative md:hidden mb-6">
          <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
          <input type="text" placeholder="Tìm kiếm..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="bg-slate-900 border border-slate-800 rounded-xl pl-10 pr-4 py-3 w-full focus:outline-none focus:border-blue-500 text-slate-200 transition-colors" />
        </div>

        {filteredVault.length === 0 ? (
          <div className="text-center py-20 bg-slate-900/50 rounded-3xl border border-slate-800 border-dashed mt-4">
            <ListFilter className="w-12 h-12 mx-auto text-slate-700 mb-4" />
            <h3 className="text-lg font-medium text-slate-300 mb-1">Trống</h3>
            <p className="text-slate-500 text-sm">Chưa có dữ liệu nào phù hợp.</p>
          </div>
        ) : (
          <div className="space-y-6">
            {Object.keys(groupedVault).sort().map(letter => (
              <div key={letter}>
                <h3 className="text-slate-500 font-semibold text-xs mb-2 px-4 uppercase tracking-wider">{letter}</h3>
                <div className="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden divide-y divide-slate-800/50 shadow-sm">
                  {groupedVault[letter].map(item => (
                    <ListRowItem 
                      key={item.id} 
                      item={item} 
                      onEdit={() => { setEditingItem(item); setShowAddModal(true); }}
                      onDelete={() => handleDeleteItem(item.id)}
                      onCopy={copyToClipboard}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      <button onClick={() => { setEditingItem(null); setShowAddModal(true); }} className="md:hidden fixed bottom-6 right-6 w-14 h-14 bg-blue-600 text-white rounded-full flex items-center justify-center shadow-[0_4px_20px_rgba(37,99,235,0.4)] z-20">
        <Plus className="w-6 h-6" />
      </button>

      {showAddModal && <ItemFormModal item={editingItem} onClose={() => setShowAddModal(false)} onSave={handleSaveItem} />}
      {toastMessage && (
        <div className="fixed bottom-8 left-1/2 transform -translate-x-1/2 bg-slate-800 text-white px-5 py-3 rounded-full shadow-2xl border border-slate-700 flex items-center z-50 whitespace-nowrap animate-in slide-in-from-bottom-5">
          <Check className="w-4 h-4 text-emerald-400 mr-2" />
          <span className="text-sm font-medium">{toastMessage}</span>
        </div>
      )}
    </div>
  );
}

// --- THÀNH PHẦN HIỂN THỊ DẠNG LIST (GIỐNG 1PASSWORD) ---
function ListRowItem({ item, onEdit, onDelete, onCopy }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const isNote = item.type === 'note';
  const initial = item.title ? item.title.charAt(0).toUpperCase() : '?';
  
  // Xử lý lấy Icon
  const iconUrl = item.customIcon || getFaviconUrl(item.url);

  return (
    <div className="transition-colors group bg-slate-900 hover:bg-slate-800/80">
      <div onClick={() => setIsExpanded(!isExpanded)} className="flex items-center justify-between p-4 cursor-pointer select-none">
        <div className="flex items-center space-x-4 overflow-hidden">
          {/* Vùng hiển thị Icon */}
          <div className={`w-10 h-10 sm:w-11 sm:h-11 rounded-[12px] flex items-center justify-center text-white font-bold text-lg flex-shrink-0 overflow-hidden shadow-inner ${!iconUrl && (isNote ? 'bg-gradient-to-br from-amber-400 to-amber-600' : 'bg-gradient-to-br from-slate-600 to-slate-700')}`}>
            {iconUrl ? (
              <img src={iconUrl} alt="icon" className="w-full h-full object-cover bg-white" onError={(e) => e.target.style.display='none'} />
            ) : isNote ? (
              <FileText className="w-5 h-5 sm:w-6 sm:h-6" />
            ) : (
              initial
            )}
          </div>
          <div className="truncate">
            <h3 className="font-semibold text-slate-200 truncate text-base">{item.title}</h3>
            <p className="text-xs sm:text-sm text-slate-500 truncate">{isNote ? 'Secure Note' : item.username}</p>
          </div>
        </div>
        <div className="flex-shrink-0 text-slate-600 group-hover:text-slate-400 transition-colors ml-4">
          {isExpanded ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
        </div>
      </div>
      
      {/* Vùng mở rộng (Chi tiết) */}
      {isExpanded && (
        <div className="px-4 pb-4 pt-1 bg-slate-900/50 border-t border-slate-800/50 cursor-default animate-in slide-in-from-top-2 duration-200">
          <div className="mt-3 space-y-3">
            {isNote ? (
              <div className="bg-slate-950/50 p-3.5 rounded-xl border border-slate-800">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-xs font-semibold text-slate-500 uppercase">Nội dung</span>
                  <div className="flex space-x-2">
                    <button onClick={() => setShowPassword(!showPassword)} className="text-slate-500 hover:text-slate-300"><Eye className="w-4 h-4" /></button>
                    <button onClick={() => onCopy(item.content)} className="text-slate-500 hover:text-blue-400"><Copy className="w-4 h-4" /></button>
                  </div>
                </div>
                <div className={`text-sm text-slate-300 whitespace-pre-wrap break-words font-mono ${!showPassword && 'blur-[4px] select-none'}`}>
                  {item.content}
                </div>
              </div>
            ) : (
              <>
                <div className="flex justify-between items-center bg-slate-950/50 p-3 rounded-xl border border-slate-800">
                  <div className="overflow-hidden pr-2">
                    <p className="text-xs font-semibold text-slate-500 uppercase mb-1">Mật khẩu</p>
                    <p className="text-sm text-slate-200 font-mono truncate">{showPassword ? item.password : '••••••••••••'}</p>
                  </div>
                  <div className="flex space-x-2 flex-shrink-0">
                    <button onClick={() => setShowPassword(!showPassword)} className="p-2 text-slate-500 hover:bg-slate-800 rounded-lg transition-colors">{showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}</button>
                    <button onClick={() => onCopy(item.password)} className="p-2 text-slate-500 hover:bg-slate-800 hover:text-blue-400 rounded-lg transition-colors"><Copy className="w-4 h-4" /></button>
                  </div>
                </div>
                <div className="flex justify-between items-center bg-slate-950/50 p-3 rounded-xl border border-slate-800">
                  <div className="overflow-hidden pr-2">
                    <p className="text-xs font-semibold text-slate-500 uppercase mb-1">Tài khoản</p>
                    <p className="text-sm text-slate-200 truncate">{item.username}</p>
                  </div>
                  <button onClick={() => onCopy(item.username)} className="p-2 text-slate-500 hover:bg-slate-800 hover:text-blue-400 rounded-lg transition-colors flex-shrink-0"><Copy className="w-4 h-4" /></button>
                </div>
              </>
            )}

            <div className="flex justify-end space-x-2 pt-2">
              {!confirmDelete ? (
                <button onClick={() => setConfirmDelete(true)} className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-rose-400 bg-slate-950 hover:bg-rose-500/10 rounded-lg border border-slate-800 transition-colors flex items-center">
                  <Trash2 className="w-3.5 h-3.5 mr-1.5" /> Xóa
                </button>
              ) : (
                <div className="flex space-x-2">
                  <button onClick={onDelete} className="px-3 py-1.5 text-xs font-bold text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition-colors">Xác nhận xóa</button>
                  <button onClick={() => setConfirmDelete(false)} className="px-3 py-1.5 text-xs font-medium text-slate-400 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors">Hủy</button>
                </div>
              )}
              <button onClick={onEdit} className="px-4 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors shadow-lg shadow-blue-600/20">Chỉnh sửa</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// --- FORM THÊM / SỬA ITEM (MODAL) ---
function ItemFormModal({ item, onClose, onSave }) {
  const [itemType, setItemType] = useState(item?.type || 'password'); 
  const [formData, setFormData] = useState({
    title: item?.title || '',
    username: item?.username || '',
    password: item?.password || '',
    url: item?.url || '',
    notes: item?.notes || '',
    content: item?.content || '',
    customIcon: item?.customIcon || '' // Field mới cho Icon tùy chỉnh
  });
  
  const [showGenerator, setShowGenerator] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave({ ...item, ...formData, type: itemType });
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-end sm:items-center justify-center sm:p-4 z-50">
      <div className="bg-slate-900 sm:rounded-3xl rounded-t-3xl border border-slate-800 w-full max-w-lg shadow-2xl flex flex-col max-h-[90vh] animate-in slide-in-from-bottom-4 sm:slide-in-from-bottom-8">
        
        <div className="px-6 py-5 border-b border-slate-800 flex justify-between items-center bg-slate-900 sticky top-0 sm:rounded-t-3xl rounded-t-3xl">
          <h2 className="text-lg font-bold text-white">
            {item ? (item.type === 'note' ? 'Sửa Ghi chú' : 'Sửa Đăng nhập') : 'Thêm Mục mới'}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1.5 rounded-full hover:bg-slate-800 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {!item && (
          <div className="flex border-b border-slate-800 bg-slate-950/50 px-2 pt-2">
            <button type="button" onClick={() => setItemType('password')} className={`flex-1 py-3 text-sm font-medium rounded-t-xl transition-colors ${itemType === 'password' ? 'bg-slate-900 text-blue-400 border-t border-x border-slate-800' : 'text-slate-500 hover:text-slate-300'}`}>Đăng nhập</button>
            <button type="button" onClick={() => setItemType('note')} className={`flex-1 py-3 text-sm font-medium rounded-t-xl transition-colors ${itemType === 'note' ? 'bg-slate-900 text-amber-400 border-t border-x border-slate-800' : 'text-slate-500 hover:text-slate-300'}`}>Ghi chú</button>
          </div>
        )}
        
        <div className="p-6 overflow-y-auto custom-scrollbar">
          {itemType === 'password' && showGenerator && (
            <div className="mb-6 p-4 bg-slate-950 rounded-2xl border border-blue-500/20">
              <h3 className="text-sm font-semibold text-blue-400 mb-3 flex items-center"><Shield className="w-4 h-4 mr-2" /> Tạo Mật khẩu an toàn</h3>
              <PasswordGenerator onApply={(pwd) => {setFormData({...formData, password: pwd}); setShowGenerator(false);}} onCancel={() => setShowGenerator(false)} />
            </div>
          )}

          <form id="item-form" onSubmit={handleSubmit} className="space-y-4.5">
            <div>
              <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Tiêu đề *</label>
              <input type="text" required value={formData.title} onChange={e => setFormData({...formData, title: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 transition-colors" placeholder="VD: Facebook, Thẻ tín dụng..." />
            </div>

            {itemType === 'password' ? (
              <>
                <div>
                  <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Tài khoản *</label>
                  <input type="text" required value={formData.username} onChange={e => setFormData({...formData, username: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 transition-colors" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Mật khẩu *</label>
                  <div className="flex space-x-2">
                    <input type="text" required value={formData.password} onChange={e => setFormData({...formData, password: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 font-mono text-lg transition-colors" />
                    <button type="button" onClick={() => setShowGenerator(!showGenerator)} className="px-3.5 bg-slate-800 text-slate-300 rounded-xl flex items-center justify-center hover:bg-slate-700 transition-colors border border-slate-700">
                      <RefreshCw className="w-5 h-5" />
                    </button>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider flex items-center gap-1.5"><Globe className="w-3.5 h-3.5"/> Trang web (URL)</label>
                  <input type="text" value={formData.url} onChange={e => setFormData({...formData, url: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 transition-colors" placeholder="facebook.com (Dùng để tự động tải Icon)" />
                </div>
              </>
            ) : (
              <div>
                <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Nội dung ghi chú *</label>
                <textarea required rows="6" value={formData.content} onChange={e => setFormData({...formData, content: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-amber-500 resize-none font-mono text-sm leading-relaxed transition-colors" placeholder="Nhập thông tin bí mật..."></textarea>
              </div>
            )}
            
            {/* Nơi dán URL Icon tùy chỉnh */}
            <div>
              <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider flex items-center gap-1.5"><ImageIcon className="w-3.5 h-3.5"/> URL Icon tùy chỉnh (Tùy chọn)</label>
              <input type="text" value={formData.customIcon} onChange={e => setFormData({...formData, customIcon: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-purple-500 transition-colors text-sm" placeholder="https://link-anh-png-cua-ban.com/icon.png" />
              <p className="text-[10px] text-slate-500 mt-1.5 ml-1">Nếu bỏ trống, hệ thống sẽ tự lấy Icon từ Trang web (URL) ở trên.</p>
            </div>
            
          </form>
        </div>
        
        <div className="px-6 py-5 border-t border-slate-800 bg-slate-900 flex justify-end space-x-3 pb-safe rounded-b-3xl">
          <button onClick={onClose} className="px-5 py-2.5 text-slate-400 bg-transparent hover:bg-slate-800 rounded-xl text-sm font-semibold transition-colors">Hủy</button>
          <button form="item-form" type="submit" className={`px-6 py-2.5 text-white rounded-xl flex items-center text-sm font-semibold transition-colors shadow-lg ${itemType === 'note' ? 'bg-amber-600 hover:bg-amber-500 shadow-amber-600/20' : 'bg-blue-600 hover:bg-blue-500 shadow-blue-600/20'}`}>
            Lưu lại
          </button>
        </div>
      </div>
    </div>
  );
}

// --- TRÌNH TẠO MẬT KHẨU TỰ ĐỘNG ---
function PasswordGenerator({ onApply, onCancel }) {
  const [length, setLength] = useState(16);
  const [useUpper, setUseUpper] = useState(true);
  const [useLower, setUseLower] = useState(true);
  const [useNumbers, setUseNumbers] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [generated, setGenerated] = useState('');

  const generatePassword = () => {
    let charset = '';
    if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (useNumbers) charset += '0123456789';
    if (useSymbols) charset += '!@#$%^&*()_+~`|}{[]:;?><,./-=';
    if (charset === '') return setGenerated('');

    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);
    let result = '';
    for (let i = 0; i < length; i++) result += charset[array[i] % charset.length];
    setGenerated(result);
  };

  useEffect(() => { generatePassword(); }, [length, useUpper, useLower, useNumbers, useSymbols]);

  return (
    <div className="space-y-4">
      <div className="flex items-center space-x-2">
        <div className="flex-grow bg-slate-900 p-3 rounded-xl border border-slate-800 text-center font-mono text-lg text-emerald-400 break-all flex items-center justify-center shadow-inner">
          {generated || "Lỗi"}
        </div>
        <button onClick={generatePassword} className="p-3 bg-slate-800 text-white rounded-xl border border-slate-700 hover:bg-slate-700 transition-colors">
          <RefreshCw className="w-5 h-5" />
        </button>
      </div>
      <div>
        <div className="flex justify-between text-sm text-slate-400 mb-2">
          <span>Độ dài:</span><span className="font-bold text-white">{length}</span>
        </div>
        <input type="range" min="8" max="64" value={length} onChange={(e) => setLength(parseInt(e.target.value))} className="w-full accent-blue-500" />
      </div>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <label className="flex items-center space-x-2 cursor-pointer"><input type="checkbox" checked={useUpper} onChange={(e) => setUseUpper(e.target.checked)} className="rounded border-slate-700 bg-slate-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-900" /><span className="text-slate-300">A-Z</span></label>
        <label className="flex items-center space-x-2 cursor-pointer"><input type="checkbox" checked={useLower} onChange={(e) => setUseLower(e.target.checked)} className="rounded border-slate-700 bg-slate-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-900" /><span className="text-slate-300">a-z</span></label>
        <label className="flex items-center space-x-2 cursor-pointer"><input type="checkbox" checked={useNumbers} onChange={(e) => setUseNumbers(e.target.checked)} className="rounded border-slate-700 bg-slate-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-900" /><span className="text-slate-300">0-9</span></label>
        <label className="flex items-center space-x-2 cursor-pointer"><input type="checkbox" checked={useSymbols} onChange={(e) => setUseSymbols(e.target.checked)} className="rounded border-slate-700 bg-slate-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-900" /><span className="text-slate-300">!@#$</span></label>
      </div>
      <div className="flex space-x-3 pt-2">
        <button onClick={onCancel} className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-sm font-medium transition-colors">Đóng</button>
        <button disabled={!generated} onClick={() => onApply(generated)} className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-semibold transition-colors disabled:opacity-50">Dùng mã này</button>
      </div>
    </div>
  );
}
