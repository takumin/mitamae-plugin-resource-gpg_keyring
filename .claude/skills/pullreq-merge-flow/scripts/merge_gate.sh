#!/usr/bin/env bash
# Codex レビューのマージゲート。背景と使いどころは ../SKILL.md にある。
#
# 使い方:
#   merge_gate.sh <PR番号>          ゲートを検査し、通れば検証済み head sha を stdout に出す
#   merge_gate.sh --merge <PR番号>  ゲートの後、その sha を前提条件に REST でマージまで行う
#                                   (Claude Code セッションではプロキシが 403 を返す。SKILL.md 参照)
#
# 環境変数:
#   GITHUB_REPO   owner/name。既定は takumin/mitamae-plugin-resource-gpg_keyring
#   GITHUB_TOKEN  あれば Authorization ヘッダに載せる (未認証の上限 60/h が 5000/h になる)
#   GITHUB_API    API のベース URL。既定は https://api.github.com (オフラインテスト用の差し替え口)
#
# 対話シェルに行ごとに貼り付けず、必ずスクリプトとして実行する。貼り付けた
# シェルでは exit 1 が検査の中断ではなくシェルの終了になる。

set -u

usage() { echo "usage: ${0##*/} [--merge] <pr-number>" >&2; exit 2; }

merge=false
if [ "${1-}" = --merge ]; then merge=true; shift; fi
case "${1-}" in '' | *[!0-9]*) usage ;; esac
n=$1

api=${GITHUB_API:-https://api.github.com}
repo=repos/${GITHUB_REPO:-takumin/mitamae-plugin-resource-gpg_keyring}

auth=()
if [ -n "${GITHUB_TOKEN-}" ]; then auth=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi

paged() {  # paged <path> [追加クエリ] -> 1 行 1 JSON オブジェクト
  local p=1 out
  while :; do
    out=$(curl -sS "${auth[@]}" "$api/$1?per_page=100&page=$p&${2-}") || return 1
    # エラーは配列ではなく JSON オブジェクトで返り、`jq length` はそのキー数を
    # 数える。空かどうかだけを見ると、拒否し続ける API に全速力で回り続ける。
    if [ "$(jq -r type <<<"$out")" != array ]; then
      echo "github api: $(jq -r '.message // .' <<<"$out")" >&2
      return 1
    fi
    [ "$(jq length <<<"$out")" -eq 0 ] && break
    jq -c '.[]' <<<"$out"
    p=$((p + 1))
  done
}

# 各一覧は読む手前で丸ごと取り切る。途中で失敗した一覧はここで検査を止める。
# `paged ... | jq ...` ではそれができない。パイプラインは最後のコマンドの
# 終了状態を報告するから、paged の return 1 は捨てられ、途切れた一覧が
# 完全な一覧の顔をして残る。
plus1=$(paged "$repo/issues/$n/reactions" "content=%2B1") || exit 1
comments=$(paged "$repo/issues/$n/comments")              || exit 1
reviews=$(paged "$repo/pulls/$n/reviews")                 || exit 1

# head は一覧の後に読む。先に読むと、一覧を歩いている間に届いた push が
# 「承認済み」として通る (置き換えられたばかりのリビジョンへの承認として)。
head=$(curl -sS "${auth[@]}" "$api/$repo/pulls/$n" | jq -r '.head.sha // empty')
[ -n "$head" ] || { echo "github api: no head sha" >&2; exit 1; }

# bot からの 👍 はあるか。content=%2B1 で 👍 だけを求めているので、ここで
# 見るのは誰が残したかだけでよい (%2B であって + ではない。+ は空白に戻る)。
plus=$(jq -r 'select(.user.login=="chatgpt-codex-connector[bot]") | .created_at' <<<"$plus1")

# 最新の判定はどれで、どのリビジョンを名指すか。クリーンな判定は issue
# コメントとして、指摘はレビュー本文として届くので両方を読む。判定の種類は
# 本文のどこにも書かれておらず、どちらの一覧から来たかだけが根拠なので、
# ここで verdict として刻む。`Reviewed commit` のない項目は落とし、bot の
# 雑談コメントがソートに勝てないようにする。
newest=$( { jq -c '. + {verdict:"clean"}'    <<<"$comments"
            jq -c '. + {verdict:"findings"}' <<<"$reviews"; } |
  jq -r 'select(.user.login=="chatgpt-codex-connector[bot]")
       | (.body | capture("Reviewed commit:\\*\\* `(?<s>[0-9a-f]+)`")? | .s) as $s
       | select($s != null)
       | [(.submitted_at // .created_at), .verdict, $s] | @tsv' | sort | tail -1)
IFS=$'\t' read -r _ kind sha <<<"$newest"

# ここまでは調べただけで何も決めていない。ここからが三つのゲートで、
# どれも素通りせず exit する。
[ -n "$plus" ]      || { echo "no: no 👍 from the bot"           >&2; exit 1; }
[ -n "$sha" ]       || { echo "no: no verdict names a revision"  >&2; exit 1; }
[ "$kind" = clean ] || { echo "no: newest verdict is $kind"      >&2; exit 1; }

# 判定が名指すのは省略形の sha。解決して head そのものであることを要求する。
# 「head がこの文字列で始まるか」は別の弱い問いで、別のコミットでも答え
# られる。解決できない省略形には GitHub が 422 を返し、`// empty` が
# 不一致に落とす。
reviewed=$(curl -sS "${auth[@]}" "$api/$repo/commits/$sha" | jq -r '.sha // empty')
[ "$reviewed" = "$head" ] ||
  { echo "no: verdict names ${reviewed:-$sha}, head is $head" >&2; exit 1; }

if ! $merge; then
  # 検証済みリビジョン。マージはこの値を名指して行う (SKILL.md の手順)。
  echo "$head"
  exit 0
fi

# --merge のときだけ、検証したリビジョンを sha 前提条件にしてマージする。
# 検査の後に届いた push は GitHub が 409 で拒否する。--fail-with-body が
# ないと curl は 409/403 でも 0 で戻り、「何もマージされていない」が成功の
# 顔をする。
curl -sS --fail-with-body -X PUT "${auth[@]}" "$api/$repo/pulls/$n/merge" \
  -d "$(jq -n --arg sha "$head" '{sha: $sha, merge_method: "merge"}')" ||
  { echo "merge refused" >&2; exit 1; }
