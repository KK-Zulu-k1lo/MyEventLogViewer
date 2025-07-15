# MyEventLogViewer

このプロジェクトは、イベントログを閲覧・管理するアプリケーションです。

## プロジェクト構成

MyEventLogViewer/ ├── initiate.sh # 初期セットアップスクリプト ├── requirements.txt # 必要なPythonライブラリのリスト └── main.py # メインアプリケーションのコード


### initiate.sh
初回セットアップ用のスクリプトです。このスクリプトを実行することで、仮想環境の設定や必要な依存関係がインストールされます。

### requirements.txt
プロジェクトで使用するすべてのPythonパッケージが記載されています。以下のコマンドでインストール可能です：
```bash
pip install -r requirements.txt

main.py
アプリケーションのエントリーポイントとなるファイルです。イベントログの処理と表示を担います。

使用方法
initiate.sh を実行して環境をセットアップします：

bash
bash initiate.sh
main.py を実行してアプリケーションを起動します：

bash
python main.py
