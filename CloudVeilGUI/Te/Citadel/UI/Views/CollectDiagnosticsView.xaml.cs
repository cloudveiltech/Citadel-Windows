﻿using CloudVeil.Windows;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Te.Citadel.UI.ViewModels;

namespace Te.Citadel.UI.Views
{
    /// <summary>
    /// Interaction logic for CollectDiagnosticsView.xaml
    /// </summary>
    public partial class CollectDiagnosticsView : UserControl
    {
        public CollectDiagnosticsView()
        {
            InitializeComponent();

            DataContext = (CitadelApp.Current as CitadelApp).ModelManager.Get<CollectDiagnosticsViewModel>();
        }
    }
}
