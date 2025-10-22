import streamlit as st
import pandas as pd
import altair as alt
from scanner import analyze_site
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
from database import init_db, add_scan, get_scans, clear_scans

def generate_pdf_report(result):
    """Génère un rapport PDF à partir du résultat du scan."""
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle("Rapport CyberGuardian")

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 800, "CyberGuardian - Rapport d'audit web")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, 770, f"Site analysé : {result['url']}")
    pdf.drawString(50, 750, f"Code HTTP : {result['status_code']}")
    pdf.drawString(50, 730, f"Connexion sécurisée : {'Oui' if result['secure'] else 'Non'}")
    pdf.drawString(50, 710, f"Score global : {result['score_percent']}%")

    pdf.line(50, 700, 550, 700)
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, 680, "Analyse des en-têtes de sécurité :")
    pdf.setFont("Helvetica", 11)

    y = 660
    for header, info in result["security_headers"].items():
        status = "✅" if info["present"] else "❌"
        text = f"{status} {header}: {info['description']}"
        pdf.drawString(60, y, text)
        y -= 15
        if y < 80:  # nouvelle page si trop bas
            pdf.showPage()
            pdf.setFont("Helvetica", 11)
            y = 800

    pdf.save()
    buffer.seek(0)
    return buffer


st.set_page_config(page_title="CyberGuardian Dashboard", page_icon="🛡️", layout="wide")
init_db()
st.title("🛡️ CyberGuardian - Analyseur de sécurité Web")

# Input URL
url = st.text_input("🌐 Entre l'URL du site à scanner (ex: google.com)")

def score_category(score):
    """Retourne (couleur_hex, label) selon le score."""
    if score >= 75:
        return "#2ecc71", "Bon"        # vert
    if score >= 40:
        return "#f39c12", "Moyen"      # orange
    return "#e74c3c", "Faible"         # rouge

def render_score_bar(score):
    """Rend une barre de progression colorée en HTML."""
    color, label = score_category(score)
    # largeur de la barre (0-100)
    width_percent = max(0, min(100, score))

    bar_html = f"""
    <div style="background: #eeeeee; border-radius: 8px; padding: 3px;">
      <div style="
        width: {width_percent}%;
        background: linear-gradient(90deg, {color}, {color});
        height: 22px;
        border-radius: 6px;
        text-align: right;
        padding-right: 8px;
        color: white;
        font-weight: bold;">
        {width_percent}%
      </div>
    </div>
    <div style="margin-top:6px; font-weight:600;">Évaluation : <span style="color:{color}">{label}</span></div>
    """
    # unsafe_allow_html permet l'HTML inline
    st.markdown(bar_html, unsafe_allow_html=True)

def render_detailed_report(security_headers):
    """Affiche un résumé lisible et les recommandations."""
    total = len(security_headers)
    ok = sum(1 for h in security_headers.values() if h["present"])
    missing = total - ok

    st.subheader("📋 Rapport détaillé")

    st.write(f"✅ **{ok}** en-têtes de sécurité présents")
    st.write(f"❌ **{missing}** en-têtes manquants")

    # Liste des headers manquants
    if missing > 0:
        st.markdown("### 🧠 Recommandations :")
        for header, info in security_headers.items():
            if not info["present"]:
                st.markdown(f"- Ajouter **{header}** → {info['description']}")
    else:
        st.markdown("🟢 Tous les en-têtes importants sont présents. Excellent travail !")


if st.button("🚀 Lancer le scan") and url:
    with st.spinner("Analyse en cours..."):
        result = analyze_site(url)

    if "error" in result:
        # Message d'erreur clair et visible
        st.error(f"❌ Erreur lors du scan : {result['error']}")
        st.info("💡 Vérifie que l'adresse est correcte et accessible (ex: https://example.com)")
    else:
        
        # ✅ Le scan a réussi        st.success(f"✅ Scan terminé pour {result['url']}")
        st.write(f"**Code HTTP :** {result['status_code']}")
        st.write(f"**Connexion sécurisée :** {'✅ HTTPS' if result['secure'] else '❌ Non sécurisé'}")
        # Enregistrer le scan dans l’historique
        add_scan(result["url"], result["score_percent"], result["secure"])


        # ---------- Score global ----------
        score = result.get("score_percent", 0)
        st.subheader("🔋 Score global de sécurité")
        render_score_bar(score)

        # ---------- Rapport détaillé ----------
        render_detailed_report(result["security_headers"])

        # ---------- Bouton PDF ----------
        pdf_data = generate_pdf_report(result)
        st.download_button(
            label="📄 Télécharger le rapport PDF",
            data=pdf_data,
            file_name=f"rapport_{result['url'].replace('https://','').replace('/','_')}.pdf",
            mime="application/pdf"
        )

        st.divider()
# === HISTORIQUE DES SCANS ===
st.subheader("📜 Historique des scans récents")

history = get_scans()

if not history:
    st.info("Aucun scan enregistré pour le moment.")
else:
    # Convertir l’historique en DataFrame
    df = pd.DataFrame(history, columns=["Site", "Score", "HTTPS", "Date"])
    df["HTTPS"] = df["HTTPS"].apply(lambda x: "✅ Oui" if x else "❌ Non")
    st.dataframe(df, use_container_width=True)

    # ---------- Graphique d'évolution ----------
    st.subheader("📊 Évolution du score de sécurité dans le temps")

    # Conversion du champ date
    df["Date"] = pd.to_datetime(df["Date"])

    # Créer le graphique avec Altair
    chart = (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X("Date:T", title="Date du scan"),
            y=alt.Y("Score:Q", title="Score de sécurité (%)"),
            color=alt.Color("Site:N", title="Site analysé"),
            tooltip=["Site", "Score", "Date"]
        )
        .properties(width=800, height=400)
        .interactive()
    )
    st.altair_chart(chart, use_container_width=True)

    # ---------- Bouton pour vider l’historique ----------
    if st.button("🧹 Effacer l’historique", key="clear_history_button"):
        clear_scans()
        st.warning("Historique effacé avec succès !")
        st.rerun()



