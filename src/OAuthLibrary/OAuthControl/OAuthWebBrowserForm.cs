﻿using System;
using System.Windows.Forms;

namespace ININ.PureCloud.OAuthControl
{
    public partial class OAuthWebBrowserForm : Form
    {
        public OAuthWebBrowserForm()
        {
            InitializeComponent();

            oAuthWebBrowser1.Authenticated += OAuthWebBrowser1OnAuthenticated;
        }

        public OAuthWebBrowserForm(string strWindowTitle) : this()
        {
            this.Text = strWindowTitle;
        }


        private void OAuthWebBrowser1OnAuthenticated(string accessToken)
        {
            try
            {
                // Close the browser
                if (!string.IsNullOrEmpty(accessToken))
                    this.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private DialogResult ShowImpl(bool dialog, IWin32Window owner = null, bool bUseOkta = false)
        {
            try
            {
                // Validate settings have been set
                if (string.IsNullOrEmpty(oAuthWebBrowser1.ClientId))
                    throw new OAuthSettingsValidationException("ClientId");
                if (string.IsNullOrEmpty(oAuthWebBrowser1.RedirectUri))
                    throw new OAuthSettingsValidationException("RedirectUri");

                // Navigate the browser (can't do this after ShowDialog has been called)
                oAuthWebBrowser1.BeginImplicitGrant(bUseOkta);

                // Open window
                if (dialog)
                    base.ShowDialog(owner);
                else
                    base.Show(owner);

                // Return result based on if we got an access token
                return string.IsNullOrEmpty(oAuthWebBrowser1.AccessToken) ? DialogResult.Cancel : DialogResult.OK;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw ex;
            }
        }

        public new DialogResult ShowDialog()
        {
            return ShowImpl(true);
        }

        public DialogResult ShowDialog(bool bUseOkta)
        {
            return ShowImpl(true, null, bUseOkta);
        }

        public new DialogResult ShowDialog(IWin32Window owner)
        {
            return ShowImpl(true, owner);
        }

        public new DialogResult Show()
        {
            return ShowImpl(false);
        }

        public new DialogResult Show(IWin32Window owner)
        {
            return ShowImpl(false, owner);
        }
    }
}
