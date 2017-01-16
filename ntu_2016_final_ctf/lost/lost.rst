
Lost
^^^^

首先用 ``tshark`` 將 pcap-ng 檔轉成 tcpdump 的格式，再用 scapy_ 開啟之；scapy 本身支援 pcap-ng 格式，但其外掛 `scapy-ssl-tls`_ 似不支援。

觀察 payload 內容發現，封包內多次傳輸相同內容，但被星號遮罩掉的位置不盡相同，所以第一步先將這些資料組起來，盡量減少星號的數量。

發現：

* KEY 前14碼已知，末兩碼未知，猜測其值域為 ``string.printable``，進行暴力破解。且一個 block 為 16bytes。
* Plaintext 已知。
* AES-CBC(KEY, Plaintext)第一個 byte、後17個 byte為已知，即最後一個 block 已知。
* AES-CBC(KEY, FLAG)已知。

依 CBC 解密流程(下圖)，:math:`$C_0 = IV$`、:math:`$P_i = D_K(C_i) \oplus C_{i-1}$`，所以 :math:`$C_{i-1} = D_K(C_i) \oplus P_i$`。

故可由猜測 :math:`$K$` 解密 :math:`$C_n$` 得到 :math:`$C_{n-1}$` 又已知 :math:`$C_{n-1}$` 的頭尾 2bytes，故解密出來的結果須符合此限制，才能確定 ``K`` 的正確性。由此 :math:`$C_{n-1}$` 再解密前一 block，便可得 :math:`$C_0 = IV$`。

.. image:: images/CBC_decryption.svg.png

至此，``IV``、``key`` 皆已知，便可將 flag 解密。

.. code-block:: python
   :include: 2_🔓Crypto/3_200_Lost/lost.py
   :start-at: ALPHA = string.printable
   :end-at: return AES_CBCd(k, binascii.unhexlify(AES_KEY_FLAG), iv)

.. _scapy: http://www.secdev.org/projects/scapy/

.. _scapy-ssl-tls: https://github.com/tintinweb/scapy-ssl_tls
